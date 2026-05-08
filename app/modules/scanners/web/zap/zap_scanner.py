import os
import time
from pathlib import Path

from loguru import logger
from pydantic import AnyUrl
from zapv2 import ZAPv2

from app.modules.scanners.web.zap.zap_context import ZapContext, ZapScanProfiles
from app.modules.interfaces.types.context import ScanContext
from modules.interfaces.scanners import IAPIScanner
from app.modules.interfaces.types.options import ScannerTaskResult
from app.modules.utils.utils import set_to_str

# This class might communicate with containers, but the class itself does not spawn them
class ZapScanner(IAPIScanner):
    _target: str
    _host: str
    report_path = f"{Path.cwd()}/app/reports/zap"
    scanner_name = "zap"
    scanner_type = "api"
    _zap_instance: ZAPv2
    _scanner_context: ZapContext
    _started: float
    _timeout = 18_000

    def __init__(self):
        self._zap_instance = ZAPv2(apikey=os.getenv("ZAP_API_KEY"), proxies={"http": "http://127.0.0.1:8090"})
        self._scanner_context = ZapContext()

    def start_scan(self, session_id: str, ctx: ScanContext) -> dict:
        logger.info(f"Starting a ZAP scan: {session_id}")
        self._started = time.monotonic()
        self._target = ctx.primary_url
        self._host = ctx.primary_host
        try:
            self.submit_scan(session_id, ctx)

            # Scanners
            self._start_trad_active_and_client_spider(session_id, ctx)
            self._start_passive_attack()
            self._start_active_attack(session_id, ctx)
            self._zap_instance.context.remove_context(session_id)

            parsed = self.parse_results(session_id)
            return ScannerTaskResult(
                scanner=self.scanner_name,
                phase="attack",
                status="success",
                result=parsed,
                runtime_ms=(time.monotonic() - self._started) * 1_000,
            ).model_dump()
        except Exception as e:
            if "timeout" in str(e).lower():
                status = "timeout"
            else:
                status = "failed"
            return ScannerTaskResult(
                scanner=self.scanner_name,
                phase="attack",
                status=status,
                result=None,
                error=str(e),
                runtime_ms=(time.monotonic() - self._started) * 1_000,
            ).model_dump()
        finally:
            self.cleanup(session_id)

    #noinspection D
    def parse_results(self, session_id: str) -> dict | None:
        import json
        logger.info(f"Parsing OWASP Zap results for session: {session_id}")
        logger.info("Waiting 60 seconds to let Zap rest...") # A hack to wait for zap requests, since if we do it instantly it does not return anything
        time.sleep(60)
        alerts = self._zap_instance.core.alerts(baseurl=self._target)
        if alerts is None:
            return None
        returnable_alerts: list = []
        har_alert_map: dict = {}
        detailed_har_map: dict = {}
        _sarif_rules: list = []
        _sarif_results: list = []
        # tracking & deduplication
        message_ids: set = set()
        rules: set = set()

        for alert in alerts:
            if alert is None:
                continue
            if alert.get("sourceMessageId") not in message_ids:
                message_ids.add(alert.get("sourceMessageId"))
            if alert["pluginId"] not in rules:
                rules.add(alert["pluginId"])
                _sarif_rules.append({
                    "id": alert["pluginId"],
                    "name": alert["name"],
                    "fullDescription": {"text": alert["description"]},
                    "help": {
                        "text": alert["solution"],
                        "markdown": "\n".join(
                            f"[{ref}]({link})" for ref, link in alert.get("tags").items() if link != ""
                        )
                    },
                    "properties": {
                        "cwe": alert.get("cweid", None),
                        "wasc": alert.get("wascid", None)
                    },
                    "level": alert.get("risk", None)
                })
            returnable_alerts.append({
                "id": alert["id"],
                "url": alert["url"],
                "sourceId": alert.get("sourceid", None),
                "method": alert["method"],
                "cweId": alert.get("cweid", None),
                "confidence": alert["confidence"],
                "sourceMessageId": alert["sourceMessageId"],
                "description": alert["description"],
                "messageId": alert["messageId"],
                "tags": alert["tags"],
                "reference": alert["reference"],
                "solution": alert["solution"],
                "alert": alert["alert"],
                "name": alert["name"],
                "risk": alert["risk"],
                "attack": alert.get("attack", None),
                "evidence": alert.get("evidence", None),
                "pluginId": alert["pluginId"]
            })

        id_string = set_to_str(message_ids)

        har_alerts = self._zap_instance.core.messages_har_by_id(ids=id_string)
        if har_alerts:
            for message in json.loads(har_alerts)["log"]["entries"]:
                if message is None:
                    continue
                har_alert_map.update({
                    message["_zapMessageId"]: {
                        "zapMessageId": message["_zapMessageId"],
                        "request": {
                            "method": message["request"]["method"],
                            "url": message["request"]["url"],
                            "headers": message["request"]["headers"] if len(
                                message["request"]["headers"]) > 0 else None,
                            "queryString": message["request"]["queryString"] if len(
                                message["request"]["queryString"]) > 0 else None,
                            "postData": message["request"]["postData"] if message["request"]["postData"] else None,
                        }
                    }
                })
        if har_alert_map.__len__() == 0:
            logger.warning("HAR alerts returned as an empty result")
            raise RuntimeWarning

        detailed_hars = self._zap_instance.core.messages_by_id(id_string)
        if detailed_hars:
            for message in detailed_hars:
                detailed_har_map.update({
                    message["id"]: {
                        "id": message["id"],
                        "requestBody": message.get("requestBody", None),
                        "requestHeader": message.get("requestHeader", None),
                        "responseBody": message.get("responseBody", None),
                        "responseHeader": message.get("responseHeader", None)
                    }
                })
        if detailed_har_map.__len__() == 0:
            logger.warning("Detailed HAR alerts returned as an empty result")

        for complete_alert in returnable_alerts:
            _associated_har = har_alert_map.get(complete_alert["sourceMessageId"])
            _associated_detailed_har = detailed_har_map.get(complete_alert["sourceMessageId"])
            _sarif_results.append({
                "ruleId": complete_alert["pluginId"],
                "message": {"text": complete_alert["description"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": AnyUrl(complete_alert["url"]).path}
                        }
                    }
                ],
                "properties": {
                    "method": complete_alert["method"],
                    "evidence": complete_alert["evidence"],
                    "confidence": complete_alert["confidence"],
                    "har": _associated_har,
                    "detailedHar": _associated_detailed_har,
                    "zapId": complete_alert["id"]
                }
            })
        _sarif_report = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "OWASP ZAP",
                            "rules": _sarif_rules
                        }
                    },
                    "results": _sarif_results
                }
            ]
        }
        with open(f"{self.report_path}/{session_id}.json", "w") as outfile:
            json.dump(_sarif_report, outfile, indent=4)
        return _sarif_report

    def cleanup(self, session_id: str) -> None:
        # logger.info("Cleaning up HTTPX artifacts")
        # Path(f"{self.report_path}/{session_id}.json").unlink(missing_ok=True)
        pass

    def submit_scan(self, session_id: str, ctx: ScanContext) -> str:
        import requests
        # Context building
        self._zap_instance.context.new_context(session_id, apikey=os.getenv("ZAP_API_KEY"))
        self._zap_instance.context.include_in_context(session_id, ctx.primary_url)
        self._zap_instance.context.include_all_context_technologies(session_id)
        # Try to catch everything
        if not ctx.primary_url.endswith("/"):
            self._zap_instance.context.include_in_context(session_id, ctx.primary_url + "/.*")
        else:
            self._zap_instance.context.include_in_context(session_id, ctx.primary_url + ".*")

        # headless configuration
        self._zap_instance.selenium.add_browser_argument("firefox", "--headless", True)

        # Traditional spider configuration
        self._zap_instance.spider.set_option_parse_sitemap_xml(True)
        self._zap_instance.spider.set_option_parse_robots_txt(True)
        self._zap_instance.spider.set_option_accept_cookies(True)
        self._zap_instance.spider.set_option_handle_o_data_parameters_visited(True)
        self._zap_instance.spider.set_option_logout_avoidance(True)
        self._zap_instance.spider.set_option_post_form(True)
        self._zap_instance.spider.set_option_process_form(True)
        self._zap_instance.spider.set_option_max_depth(5)

        # Ajax spider configuration
        self._zap_instance.ajaxSpider.set_option_enable_extensions(True)
        self._zap_instance.ajaxSpider.set_option_reload_wait(30)
        self._zap_instance.ajaxSpider.set_option_event_wait(4_500)  # wait 4.5s
        self._zap_instance.ajaxSpider.set_option_max_crawl_depth(5)
        self._zap_instance.ajaxSpider.set_option_browser_id("firefox-headless")
        self._zap_instance.ajaxSpider.set_option_number_of_browsers(1)
        self._zap_instance.ajaxSpider.set_option_random_inputs(True)

        # passive attack
        self._zap_instance.pscan.enable_all_scanners()
        self._zap_instance.pscan.enable_all_tags()

        # active attack
        self._zap_instance.ascan.enable_all_scanners()
        self._zap_instance.ascan.set_option_handle_anti_csrf_tokens(True)
        self._zap_instance.ascan.set_option_scan_headers_all_requests(True)
        self._zap_instance.ascan.set_option_add_query_param(True)
        self._zap_instance.ascan.set_option_thread_per_host(2)
        self._zap_instance.ascan.set_option_default_policy(ZapScanProfiles.PENTEST)  # this is set by the user later
        self._zap_instance.ascan.set_option_max_rule_duration_in_mins(120)
        
        # misc configurations

        # avoid logout elements
        try:
            response = requests.get(
                url="http://localhost:8090/JSON/ajaxSpider/action/setOptionLogoutAvoidance/",
                params={
                    "Boolean": True
                },
                headers={
                    "X-ZAP-API-Key": os.getenv('ZAP_API_KEY')
                },
                timeout=10
            )
            response.raise_for_status()
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.error("There was something wrong whilst setting an ajaxSpider option!")
            logger.exception(e)
        except requests.exceptions.HTTPError as e:
            logger.error("There was something wrong whilst setting an ajaxSpider option!")
            logger.exception(e)
        return "configured"

    def poll_scan(self, scan_ref: str) -> dict:
        raise NotImplementedError

    def _start_trad_active_and_client_spider(self, session_id:str, ctx: ScanContext):
        from loguru import logger
        from time import sleep
        logger.info("Starting discovery with zap crawlers")
        try:
            # Traditional Spider
            scan_id = self._zap_instance.spider.scan(
                url=ctx.primary_url,
                # recurse=True,
                contextname=session_id,
            )
            sleep(5)
            logger.info("Starting traditional spider")
            while int(self._zap_instance.spider.status(scan_id)) < 100:
                sleep(5)
            logger.success("traditional spider completed")

            self._zap_instance.ajaxSpider.scan(
                url=ctx.primary_url,
                contextname=session_id
            )
            sleep(5)
            logger.info("Starting ajax spider")
            while self._zap_instance.ajaxSpider.status == "running":
                sleep(5)
            logger.success("ajax spider completed")

            scan_id = self._zap_instance.clientSpider.scan(
                url=ctx.primary_url,
                maxcrawldepth=5,
                pageloadtime=30,
                numberofbrowsers=1,
                contextname=session_id,
                scopecheck="STRICT"
            )
            sleep(5)
            logger.info("Starting client spider")
            while int(self._zap_instance.clientSpider.status(scan_id)) < 100:
                sleep(5)
            logger.success("client spider completed")
        except Exception as e:
            logger.error("Something happened to zap!")
            raise e

    def _start_passive_attack(self):
        from loguru import logger
        from time import sleep
        try:
            logger.info("Starting passive attack mode")
            while int(self._zap_instance.pscan.records_to_scan) > 0:
                sleep(5)
        except Exception as e:
            logger.error("Something happened to zap!")
            raise e

    def _start_active_attack(self, session_id:str, ctx: ScanContext):
        from loguru import logger
        from time import sleep
        logger.info("Starting active attack mode")
        try:
            scan_id = self._zap_instance.ascan.scan(
                url=ctx.primary_url,
                contextid=self._zap_instance.context.context(session_id)['id']
            )
            while int(self._zap_instance.ascan.status(scan_id)) < 100:
                sleep(5)
            logger.success("active scan completed")
        except Exception as e:
            logger.error("Something happened to zap!")
            raise e