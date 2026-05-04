import subprocess
import time
from pathlib import Path
from loguru import logger

from app.modules.scanners.web.wapiti.wapiti_config_builder import WapitiConfigBuilder, WapitiConfig
from app.modules.interfaces.types.context import ScanContext, redis_client
from app.modules.interfaces.enums.scanners import ICliScanner
from app.modules.interfaces.types.options import ScannerTaskResult
from app.modules.tasks.discovery.discovery_context import DiscoveryContext


class WapitiScanner(ICliScanner):
    report_path = f"{Path.cwd()}/app/reports/wapiti"
    scanner_name = "wapiti"
    scanner_type = "cli"
    _wstg_to_json_path = f"{Path.cwd()}/app/modules/scanners/web/wapiti/templates/wstg_to_cve.json"
    _config: WapitiConfig
    _builder: WapitiConfigBuilder
    _timeout = 18_000

    def __init__(self):
        self.config = WapitiConfig()
        self._builder = WapitiConfigBuilder(self.config)

    def start_scan(self, session_id: str, ctx: ScanContext) -> dict:
        logger.info(f"Starting a wapiti scan: {session_id}")
        started = time.monotonic()

        try:
            commands: list = self.build_command(session_id, ctx)
            # Context from discovery
            raw = redis_client.get(f"discovery:{session_id}")
            if raw is None:
                raise ValueError(f"Missing discovery context for session {session_id}")
            _discovery_context: DiscoveryContext = DiscoveryContext.model_validate_json(raw)
            assert _discovery_context.technologies is not None

            process = subprocess.Popen(
                commands
            )
            process.wait()
            if process.returncode != 0:
                raise subprocess.SubprocessError

            return ScannerTaskResult(
                scanner=self.scanner_name,
                phase="attack",
                status="success",
                result=self.parse_results(session_id),
                stdout=None,
                exit_code=process.returncode,
                runtime_ms=(time.monotonic() - started) * 1_000,
            ).model_dump()
        except subprocess.TimeoutExpired as e:
            return ScannerTaskResult(
                scanner=self.scanner_name,
                phase="attack",
                status="timeout",
                result=None,
                error=f"{self.scanner_name} exceeded timeout",
                stdout=str(e.stdout),
                stderr=str(e.stderr),
                runtime_ms=(time.monotonic() - started) * 1_000,
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
                runtime_ms=(time.monotonic() - started) * 1_000,
            ).model_dump()
        finally:
            self.cleanup(session_id)

    # noinspection D
    def parse_results(self, session_id: str) -> dict:
        """Parses generated report to SARIF v2.1.0
                :param session_id: The path of the report to parse
                :return: The parsed report"""
        import json
        logger.debug(f"Parsing Wapiti results for session: {session_id}")
        sarif_report = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Wapiti3",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }
        with open(f"{self.report_path}/{session_id}.json", "r") as report:
            report = json.load(report)
            self._parse_definitions_to_sarif(sarif_report, report)
            for category in report["vulnerabilities"]:
                if len(report["vulnerabilities"][category]) != 0:
                    for vulnerability in report["vulnerabilities"][category]:
                        result = {"ruleId": category, "locations": [], "properties": {}}
                        for key, value in vulnerability.items():
                            match key:
                                case "level":
                                    self._parse_level_to_sarif(value, result)
                                case "info":
                                    result.update({"message": {"text": value}})
                                case "path":
                                    result["locations"].append(
                                        {"physicalLocation": {"artifactLocation": {"uri": value}}})
                                case _:
                                    if key == "wstg":
                                        result["properties"].update({"wstg": value})
                                    result["properties"].update({key: value})
                    sarif_report["runs"][0]["results"].append(result)
        return sarif_report


    def cleanup(self, session_id: str) -> None:
        pass

    def build_command(self, session_id: str, ctx: ScanContext) -> list[str]:
        # localtest = ["http://10.89.4.3"] # test line
        # wapiti_url = ctx.primary_url # test line
        # if wapiti_url in localtest: # test line
        #     wapiti_url = "http://localhost:4280" #test line
        return (
            self._builder
            .url(ctx.primary_url)
            .output(f"{self.report_path}/{session_id}.json")
            .build()
        )

    #noinspection D
    def _parse_definitions_to_sarif(self, sarif_report, report):
        """Parses Wapiti3's vulnerability definitions to sarif. This function has an intended side effect of mutating the rule variable.
        :param sarif_report: dictionary to modify
        :param report: report to read and rewrite
        """
        import json
        with open(self._wstg_to_json_path, "r") as file:
            mapping = json.load(file)
            for category in report["vulnerabilities"]:
                rule = {"id": category, "shortDescription": {"text": category}}
                for key, value in report["classifications"][category].items():
                    match key:
                        case "desc":
                            rule.update({"fullDescription": {"text": value}})
                        case "sol":
                            rule.update({"help": {"text": value}})
                        case "ref":
                            markdown = "References:\n"
                            for title, link in value.items():
                                markdown.join("\n[{}]({})".format(title, link))
                            rule["help"].update({"markdown": value})
                        case "wstg":
                            _list = []
                            if category in mapping:
                                _list.append(mapping[category])
                                for wstg in value:
                                    _list.append(wstg)
                            rule.update({"properties": {"tags": _list}})
                sarif_report["runs"][0]["tool"]["driver"]["rules"].append(rule)

    def _parse_level_to_sarif(self, level: int, result: dict):
        """Parses Wapiti's level information to sarif. A util function
        :param level:
        :param result: dictionary to modify"""
        if level == 0:
            result.update({"level": "note"})
        elif level == 1:
            result.update({"level": "warning"})
        else:
            result.update({"level": "error"})