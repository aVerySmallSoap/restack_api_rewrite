import time
from pathlib import Path

from docker.models.containers import Container
from loguru import logger

from app.modules.interfaces.enums.scanners import IContainerScanner
from app.modules.interfaces.types.options import ScannerTaskResult
from modules.interfaces.types.context import ScanContext
from app.modules.scanners.web.nuclei.nuclei_context import NucleiContext


class Nuclei(IContainerScanner):
    report_path = f"{Path.cwd()}/app/reports/nuclei"
    scanner_name = "nuclei"
    scanner_type = "container"
    _scanner_context: NucleiContext
    _timeout = 18_000

    def __init__(self):
        self._scanner_context = NucleiContext()

    def start_scan(self, session_id: str, ctx: ScanContext) -> dict:
        logger.info(f"Starting Nuclei scan: {session_id}")
        started = time.monotonic()

        try:
            container = self.spawn_container(session_id, ctx)
            container_result = container.wait(timeout=self._timeout)
            exit_code = container_result.get("StatusCode")
            assert isinstance(container, Container)
            logs = container.logs(stdout=True, stderr=True).decode(errors="replace")
            if exit_code != 0:
                logger.error(f"Katana has exited abruptly on exit code: {exit_code}")
                return ScannerTaskResult(
                    scanner="katana",
                    phase="preamble",
                    status="failed",
                    result=None,
                    error=f"Katana exited with code {exit_code}",
                    stdout=logs,
                    stderr=None,
                    exit_code=exit_code,
                    runtime_ms=int((time.monotonic() - started) * 1000),
                ).model_dump()

            parsed = self.parse_results(session_id)
            return ScannerTaskResult(
                scanner="katana",
                phase="preamble",
                status="success",
                result=parsed,
                stdout=logs,
                exit_code=exit_code,
                runtime_ms=int((time.monotonic() - started) * 1000),
            ).model_dump()
        except Exception as e:
            if "timeout" in str(e).lower():
                status = "timeout"
            else:
                status = "failed"
            return ScannerTaskResult(
                scanner="nuclei",
                phase="attack",
                status=status,
                result=None,
                error=str(e),
                runtime_ms=int((time.monotonic() - started) * 1000),
            ).model_dump()
        finally:
            # self.cleanup(session_id)
            pass

    def parse_results(self, session_id: str) -> dict:
        # TODO: implement
        pass

    def cleanup(self, session_id: str) -> None:
        # TODO: implement
        pass

    def spawn_container(self, session_id: str, ctx: ScanContext) -> Container:
        import docker
        logger.info(f"Spawning container: {self.scanner_name}_{session_id}")
        client = docker.from_env()
        return client.containers.run(
            image="projectdiscovery/nuclei",
            name=f"{self.scanner_name}_{session_id}",
            command=[
                "-u", ctx.primary_url,
                "-v",
                "-j",
                "-o", f"/reports/{session_id}.json",
                "-etags", "wp-plugin" # TODO: remove @ prod
                "-fhr",
                # "-dast", # Dast should be a separate task in celery
                "-duc" # Templates are updated before the server starts
            ],
            volumes={
                self.report_path: {
                    "bind": "/reports/",
                    "mode": "rw",
                },
                f"{Path.cwd()}/app/templates/nuclei/": {
                    "bind": "/root/nuclei-templates",
                    "mode": "ro"
                }
            },
            detach=True,
            auto_remove=False,
        )

    def spawn_headless_container(self, session_id: str, ctx: ScanContext) -> Container:
        import docker
        logger.info(f"Spawning container: {self.scanner_name}_headless_{session_id}")
        client = docker.from_env()
        return client.containers.run(
            image="projectdiscovery/nuclei",
            name=f"{self.scanner_name}_headless_{session_id}",
            command=[],
            volumes={
                self.report_path: {
                    "bind": "/reports/",
                    "mode": "rw",
                }
            },
            detach=True,
            auto_remove=False,
        )