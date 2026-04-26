import json
import os
import time
from pathlib import Path

from docker.models.containers import Container
from loguru import logger

from app.modules.pipeline.context import ScanContext
from app.modules.interfaces.enums.scanners import IContainerScanner
from app.modules.interfaces.types.options import ScannerTaskResult

class Subfinder(IContainerScanner):
    report_path = f"{Path.cwd()}/app/reports/subfinder"
    scanner_type = "container"
    scanner_name = "subfinder"
    _timeout = 300

    def start_scan(self, session_id: str, ctx: ScanContext) -> dict:
        logger.info(f"Starting Subfinder scan: {session_id}")
        started = time.monotonic()

        try:
            container = self.spawn_container(session_id, ctx)
            result = container.wait(timeout=self._timeout)
            exit_code = result.get("StatusCode")
            logs = container.logs(stdout=True, stderr=True).decode(errors="replace")

            if exit_code != 0:
                logger.error(f"Subfinder has exited abruptly on exit code: {exit_code}")
                return ScannerTaskResult(
                    scanner="subfinder",
                    phase="preamble",
                    status="failed",
                    result=None,
                    error=f"Subfinder exited with code {exit_code}",
                    stdout=logs,
                    stderr=None,
                    exit_code=exit_code,
                    runtime_ms=int((time.monotonic() - started) * 1000),
                ).model_dump()

            parsed = self.parse_results(session_id)
            return ScannerTaskResult(
                scanner="subfinder",
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
                scanner="subfinder",
                phase="preamble",
                status=status,
                result=None,
                error=str(e),
                runtime_ms=int((time.monotonic() - started) * 1000),
            ).model_dump()
        finally:
            self.cleanup(session_id)

    def parse_results(self, session_id: str) -> dict:
        logger.info(f"Parsing Subfinder results for session: {session_id}")
        path = f"{self.report_path}/{session_id}.json"
        if os.path.getsize(path) == 0:
            return None
        with open(path) as f:
            base_input = json.loads(f.readline()).get("input")
            sources: set = set()
            hosts: list = []
            for line in f.read().splitlines():
                record: dict = json.loads(line)
                record_sources = record.get("sources")
                assert isinstance(record_sources, list)
                for source in record_sources:
                    sources.add(source)
                hosts.append(record.get("host"))
        return {
            base_input: {
                "hosts": hosts,
                "sources": list(sources)
            }
        }

    def cleanup(self, session_id: str) -> None:
        import docker
        logger.info("Cleaning up Subfinder artifacts")
        # Path(f"{self._base_report_path}/{session_id}.json").unlink(missing_ok=True)
        client = docker.from_env()
        try:
            container = client.containers.get(f"{self.scanner_name}_{session_id}")
            container.stop(timeout=5)
            # container.remove()
        except docker.errors.NotFound:
            logger.warning(f"Could not find container with ID: subfinder_{session_id}. Skipping cleanup")

    def spawn_container(self, session_id: str, ctx: ScanContext) -> Container:
        import docker
        logger.info(f"Spawning container: {self.scanner_name}_{session_id}")
        client = docker.from_env()
        return client.containers.run(
            image="projectdiscovery/subfinder",
            name=f"{self.scanner_name}_{session_id}",
            command=[
                "-all",
                "-cs",
                "-oJ",
                "-o", f"/reports/{session_id}.json",
                "-d", ctx.primary_host
            ],
            volumes={
                self.report_path: {
                    "bind": "/reports/",
                    "mode": "rw",
                }
            },
            detach=True,
            auto_remove=False,
        )

    def spawn_headless_container(self, session_id: str, ctx: ScanContext) -> Container:
        raise NotImplementedError