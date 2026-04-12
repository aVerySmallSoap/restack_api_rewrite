import os
from pathlib import Path

from zapv2 import ZAPv2

from app.modules.interfaces.base import IScanner
from app.modules.scanners.web.zap.zap_context import ZapContext, ZapScanProfiles
from app.modules.pipeline.context import DiscoveryContext


# This class might communicate with containers, but the class itself does not spawn them
class ZapScanner(IScanner):
    _zap_instance: ZAPv2
    _base_report_path = f"{Path.cwd()}/app/reports/zap"
    _prefix = "zap"
    _scanner_context: ZapContext

    def __init__(self):
        self._zap_instance = ZAPv2(apikey=os.getenv("ZAP_API_KEY"), proxies={"http": "http://127.0.0.1:8090"})
        self._scanner_context = ZapContext()

    def start_scan(self, session_id: str, ctx: DiscoveryContext) -> dict: # This should not use discovery context but WebContext
        # Context building
        self._zap_instance.context.new_context(session_id)
        self._zap_instance.context.include_in_context(session_id, ctx.primary_url)
        self._zap_instance.context.include_all_context_technologies(session_id)
        # Try to catch everything
        if not ctx.primary_url.endswith("/"):
            self._zap_instance.context.include_in_context(session_id, ctx.primary_url + "/.*")
        else:
            self._zap_instance.context.include_in_context(session_id, ctx.primary_url + ".*")

        # headless configuration
        self._zap_instance.selenium.add_browser_argument("firefox", "--headless", True)

        # Scanners
        sitemap = self._start_trad_active_and_client_spider(session_id, ctx)
        passive_alerts = self._start_passive_attack(ctx)
        active_alerts = self._start_active_attack(session_id, ctx)
        self._zap_instance.core.jsonreport()
        self._zap_instance.context.remove_context(session_id)

        with open(f"{self._base_report_path}/{session_id}.json", "w") as f:
            # temporary write
            import json
            f.write(json.dumps({
                "sitemap": sitemap,
                "alerts": {
                    "passive": passive_alerts,
                    "active": active_alerts
                }
            }, indent=4))
        return self._parse_results(session_id)

    def _parse_results(self, session_id: str) -> dict:
        # self._zap_instance.core.delete_all_alerts()
        pass

    def _cleanup(self, session_id: str) -> None:
        pass

    def _start_trad_active_and_client_spider(self, session_id:str, ctx: DiscoveryContext):
        from loguru import logger
        from time import sleep
        import requests
        logger.info("Starting discovery with zap crawlers")
        try:
            # TODO: Move to a config function
            # try and set options first
            self._zap_instance.spider.set_option_parse_sitemap_xml(True)
            self._zap_instance.spider.set_option_parse_robots_txt(True)
            self._zap_instance.spider.set_option_accept_cookies(True)
            self._zap_instance.spider.set_option_handle_o_data_parameters_visited(True)
            self._zap_instance.spider.set_option_logout_avoidance(True)
            self._zap_instance.spider.set_option_post_form(True)
            self._zap_instance.spider.set_option_process_form(True)
            self._zap_instance.spider.set_option_max_depth(5)

            self._zap_instance.ajaxSpider.set_option_enable_extensions(True)
            self._zap_instance.ajaxSpider.set_option_reload_wait(30)
            self._zap_instance.ajaxSpider.set_option_event_wait(4_500) # wait 4.5s
            self._zap_instance.ajaxSpider.set_option_max_crawl_depth(5)
            self._zap_instance.ajaxSpider.set_option_browser_id("firefox-headless")
            self._zap_instance.ajaxSpider.set_option_number_of_browsers(1)
            self._zap_instance.ajaxSpider.set_option_random_inputs(True)

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
            print(f"Trad tree: {self._zap_instance.spider.results(scan_id)}")

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
            # Dump site maps and all the good things here
            return self._zap_instance.core.urls(baseurl=ctx.primary_host)
        except Exception as e:
            logger.error("Something happened to zap!")
            raise e

    def _start_passive_attack(self, ctx: DiscoveryContext):
        from loguru import logger
        from time import sleep
        try:
            logger.info("Starting passive attack mode")
            self._zap_instance.pscan.enable_all_scanners()
            self._zap_instance.pscan.enable_all_tags()
            while int(self._zap_instance.pscan.records_to_scan) > 0:
                sleep(5)
            alerts = self._zap_instance.core.alerts(baseurl=ctx.primary_host)
            print(alerts)
            return alerts
        except Exception as e:
            logger.error("Something happened to zap!")
            raise e

    def _start_active_attack(self, session_id:str, ctx: DiscoveryContext):
        from loguru import logger
        from time import sleep
        logger.info("Starting active attack mode")
        try:
            self._zap_instance.ascan.enable_all_scanners()
            self._zap_instance.ascan.set_option_handle_anti_csrf_tokens(True)
            self._zap_instance.ascan.set_option_scan_headers_all_requests(True)
            self._zap_instance.ascan.set_option_add_query_param(True)
            self._zap_instance.ascan.set_option_thread_per_host(2)
            self._zap_instance.ascan.set_option_default_policy(ZapScanProfiles.PENTEST) # this is set by the user later

            scan_id = self._zap_instance.ascan.scan(
                url=ctx.primary_url,
                contextid=self._zap_instance.context.context(session_id)['id']
            )
            while int(self._zap_instance.ascan.status(scan_id)) < 100:
                sleep(5)
            logger.success("active scan completed")
            alerts = self._zap_instance.core.alerts(baseurl=ctx.primary_host)
            print(alerts)
            return alerts
        except Exception as e:
            logger.error("Something happened to zap!")
            raise e
