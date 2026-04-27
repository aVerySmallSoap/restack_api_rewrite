import subprocess
import time
from pathlib import Path
from loguru import logger

from app.modules.scanners.web.wapiti.wapiti_config_builder import WapitiConfigBuilder, WapitiConfig
from modules.interfaces.types.context import ScanContext, redis_client
from app.modules.interfaces.enums.scanners import ICliScanner
from app.modules.interfaces.types.options import ScannerTaskResult
from app.modules.tasks.discovery.discovery_context import DiscoveryContext


class WapitiScanner(ICliScanner):
    report_path = f"{Path.cwd()}/app/reports/wapiti"
    scanner_name = "wapiti"
    scanner_type = "cli"
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

            process = subprocess.run(
                commands,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False
            )
            if process.returncode != 0:
                raise subprocess.SubprocessError

            return ScannerTaskResult(
                scanner=self.scanner_name,
                phase="attack",
                status="success",
                result=self.parse_results(session_id),
                stdout=process.stdout,
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


    def parse_results(self, session_id: str) -> dict:
        pass

    def cleanup(self, session_id: str) -> None:
        pass

    def build_command(self, session_id: str, ctx: ScanContext) -> list[str]:
        return (
            self._builder
            .url(ctx.primary_url)
            .output(f"{self.report_path}/{session_id}.json")
            .build()
        )