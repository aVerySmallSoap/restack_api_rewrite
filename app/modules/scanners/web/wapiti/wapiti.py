from pathlib import Path

from docker.models.containers import Container

from app.modules.interfaces.base import IScanner
from app.modules.interfaces.options import BaseContext
from modules.pipeline.context import DiscoveryContext


class Wapiti(IScanner):
    _base_report_path: str = f"{Path.cwd()}/app/reports/wapiti"
    _prefix: str = "wapiti"
    _scanner_context: BaseContext = None

    def start_scan(self, session_id: str, ctx: DiscoveryContext) -> dict:
        pass

    def parse_results(self, session_id: str) -> dict:
        pass

    def _cleanup(self, session_id: str) -> None:
        pass