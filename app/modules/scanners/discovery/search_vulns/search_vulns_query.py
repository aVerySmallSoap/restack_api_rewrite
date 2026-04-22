import json
import subprocess
from pathlib import Path

from loguru import logger

from app.modules.interfaces.base import IScanner
from app.modules.utils.utils import compile_and_parse_to_search_vuln_queriable, resolve_tech_to_tech_entry
from app.modules.pipeline.context import ScanContext, redis_client
from app.modules.tasks.discovery.discovery_context import DiscoveryContext


class SearchVulnsQuery(IScanner):
    _base_report_path = f"{Path.cwd()}/app/reports/search_vulns"
    _commands: list[str] = ["search_vulns", "-f", "json", "--output"]
    _discovery_context: DiscoveryContext

    def start_scan(self, session_id: str, ctx: ScanContext) -> dict:
        logger.info(f"Querying vulnerabilities related to the discovered technologies on: {session_id}")
        self._commands.append(f"{self._base_report_path}/{session_id}.json")
        raw = redis_client.get(f"discovery:{session_id}")
        if raw is None:
            raise ValueError(f"Missing discovery context for session {session_id}")
        self._discovery_context: DiscoveryContext = DiscoveryContext.model_validate_json(raw)
        assert self._discovery_context.technologies is not None
        try:
            process = subprocess.Popen(
                compile_and_parse_to_search_vuln_queriable(
                    self._discovery_context.technologies,
                    self._commands),
                stdout=subprocess.PIPE)
            process.wait()
            if process.returncode != 0:
                raise subprocess.SubprocessError
        except subprocess.SubprocessError:
            pass
        return self._parse_results(session_id)

    def _parse_results(self, session_id: str) -> dict:
        with open(f"{self._base_report_path}/{session_id}.json") as f:
            json_data = json.load(f)
            _returnable = []
            for tech, info in json_data.items():
                if type(info) is str:
                    continue
                _returnable.append({tech: info})
        self._discovery_context.queried_vulnerabilities = _returnable
        redis_client.set(f"discovery:{session_id}", self._discovery_context.model_dump_json())
        with open(f"{Path.cwd()}/app/reports/test.json", "w") as f:
            f.write(json.dumps(self._discovery_context.model_dump_json(), indent=4))
        return {
            "vulnerable_technologies": _returnable
        }

    def _cleanup(self, session_id: str) -> None:
        pass