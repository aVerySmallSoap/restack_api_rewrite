import json
import subprocess
import time
from pathlib import Path

from loguru import logger

from app.modules.utils.utils import compile_and_parse_to_search_vuln_queriable, is_file_empty
from app.modules.interfaces.types.context import ScanContext, redis_client
from app.modules.tasks.discovery.discovery_context import DiscoveryContext
from app.modules.interfaces.scanners import ICliScanner
from app.modules.interfaces.types.options import ScannerTaskResult


class SearchVulnsQuery(ICliScanner):
    report_path = f"{Path.cwd()}/app/reports/search_vulns"
    scanner_name = "search_vulns"
    scanner_type = "cli"
    _commands: list[str] = ["search_vulns", "-f", "json", "--output"]
    _discovery_context: DiscoveryContext
    _timeout=300

    def start_scan(self, session_id: str, ctx: ScanContext) -> ScannerTaskResult:
        logger.info(f"Querying vulnerabilities related to the discovered technologies on: {session_id}")
        started = time.monotonic()
        try:
            self._commands.append(f"{self.report_path}/{session_id}.json")
            raw = redis_client.get(f"discovery:{session_id}")
            if raw is None:
                raise ValueError(f"Missing discovery context for session {session_id}")
            self._discovery_context: DiscoveryContext = DiscoveryContext.model_validate_json(raw)
            assert self._discovery_context.technologies is not None

            process = subprocess.run(
                compile_and_parse_to_search_vuln_queriable(
                    self._discovery_context.technologies,
                    self._commands),
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False
            )
            if process.returncode != 0:
                raise subprocess.SubprocessError

            return ScannerTaskResult(
                scanner=self.scanner_name,
                phase="vuln_query",
                status="success",
                result=self.parse_results(session_id),
                stdout=process.stdout,
                exit_code=process.returncode,
                runtime_ms=(time.monotonic() - started) * 1_000,
            ).model_dump()
        except subprocess.TimeoutExpired as e:
            return ScannerTaskResult(
                scanner=self.scanner_name,
                phase="vuln_query",
                status="timeout",
                result=None,
                error=f"{self.scanner_name} exceeded timeout",
                stdout=str(e.stdout),
                stderr=str(e.stderr),
                runtime_ms=(time.monotonic() - started) * 1_000
            ).model_dump()
        except Exception as e:
            if "timeout" in str(e).lower():
                status = "timeout"
            else:
                status = "failed"
            return ScannerTaskResult(
                scanner="whatweb",
                phase="asset",
                status=status,
                result=None,
                error=str(e),
                runtime_ms=(time.monotonic() - started) * 1_000,
            ).model_dump()
        finally:
            # self.cleanup(session_id)
            pass
    def parse_results(self, session_id: str) -> dict | None:
        logger.info(f"Parsing search_vulns queries for session: {session_id}")
        path = f"{self.report_path}/{session_id}.json"
        try:
            if is_file_empty(path):
                raise RuntimeWarning
            with open(path, "r") as f:
                json_data = json.load(f)
                _returnable = []
                for tech, info in json_data.items():
                    if type(info) is str:
                        continue
                    _returnable.append({tech: info})
            self._discovery_context.queried_vulnerabilities = _returnable
            redis_client.set(f"phase:{session_id}", "vuln_query")
            redis_client.set(f"discovery:{session_id}", self._discovery_context.model_dump_json())
            return {
                "vulnerable_technologies": _returnable
            }
        except RuntimeWarning:
            logger.warning("Search_Vulns report file empty! Was there any scanner errors?")
            return None
        except AssertionError as e:
            logger.error("Search_Vulns parsing has encountered an unexpected type!")
            logger.exception(e)
            raise RuntimeError

    def cleanup(self, session_id: str) -> None:
        pass

    def build_command(self, session_id: str, ctx: ScanContext) -> list[str]:
        pass