import subprocess
from pathlib import Path
from loguru import logger

from app.modules.interfaces.base import IScanner
from app.modules.scanners.web.wapiti.wapiti_config_builder import WapitiConfigBuilder, WapitiConfig
from app.modules.pipeline.context import ScanContext
from app.modules.scanners.web.wapiti.wapiti_context import WapitiContext

class WapitiScanner(IScanner):
    _base_report_path: str = f"{Path.cwd()}/app/reports/wapiti"
    _prefix: str = "wapiti"
    _scanner_context: WapitiContext
    _config: WapitiConfig
    _builder: WapitiConfigBuilder

    def __init__(self):
        self._scanner_context = WapitiContext()
        self.config = WapitiConfig()
        self._builder = WapitiConfigBuilder(self.config)

    def start_scan(self, session_id: str, ctx: ScanContext) -> dict:
        logger.info(f"Starting a wapiti scan: {session_id}")
        # build
        commands: list = (self._builder
                          .url(ctx.primary_url)
                          .output(f"{self._base_report_path}/{session_id}.json")
                          .build())

        # runE
        try:
            process = subprocess.Popen(commands)
            process.wait()
            if process.returncode != 0:
                raise subprocess.SubprocessError
        except subprocess.SubprocessError:
            pass
        except subprocess.CalledProcessError:
            pass
        # parse
        return self._parse_results(ctx.session_id)

    def _parse_results(self, session_id: str) -> dict:
        pass

    def _cleanup(self, session_id: str) -> None:
        pass