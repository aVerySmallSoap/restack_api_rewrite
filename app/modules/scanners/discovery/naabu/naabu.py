import json
import time
from pathlib import Path

import docker
from docker.models.containers import Container
from loguru import logger

from modules.interfaces.types.context import ScanContext
from app.modules.interfaces.enums.scanners import IContainerScanner
from app.modules.interfaces.types.options import ScannerTaskResult
from app.modules.utils.utils import is_file_empty


class Naabu(IContainerScanner):
    report_path = f"{Path.cwd()}/app/reports/naabu"
    scanner_type = "container"
    scanner_name = "naabu"
    _timeout = 300

    def start_scan(self, session_id: str, ctx: ScanContext) -> dict:
        logger.info(f"Starting Naabu scan: {session_id}")
        started = time.monotonic()
        try:
            container = self.spawn_container(session_id, ctx)
            result = container.wait(timeout=self._timeout)
            exit_code = result.get("StatusCode")
            logs = container.logs(stdout=True, stderr=True).decode(errors="replace")

            if exit_code != 0:
                logger.error(f"Naabu has exited abruptly on exit code: {exit_code}")
                return ScannerTaskResult(
                    scanner="naabu",
                    phase="preamble",
                    status="failed",
                    result=None,
                    error=f"Naabu exited with code {exit_code}",
                    stdout=logs,
                    stderr=None,
                    exit_code=exit_code,
                    runtime_ms=(time.monotonic() - started) * 1_000,
                ).model_dump()

            parsed = self.parse_results(session_id)

            return ScannerTaskResult(
                scanner="naabu",
                phase="preamble",
                status="success",
                result=parsed,
                stdout=logs,
                exit_code=exit_code,
                runtime_ms=(time.monotonic() - started) * 1_000,
            ).model_dump()

        except Exception as e:
            if "timeout" in str(e).lower():
                status = "timeout"
            else:
                status = "failed"
            return ScannerTaskResult(
                scanner="naabu",
                phase="preamble",
                status=status,
                result=None,
                error=str(e),
                runtime_ms=(time.monotonic() - started) * 1_000,
            ).model_dump()

        finally:
            self.cleanup(session_id)

    def parse_results(self, session_id: str) -> dict | None:
        logger.info(f"Parsing Naabu results for session: {session_id}")
        ports: list[int] = []
        base_report = f"{self.report_path}/{session_id}.json"

        try:
            if is_file_empty(base_report):
                raise RuntimeWarning
            with open(base_report, "r") as f:
                for line in f.read().splitlines():
                    record = json.loads(line) # TODO: also check if the ip is the same
                    ports.append(record["port"])
            return {"ports": ports}
        except RuntimeWarning:
            logger.warning("Naabu report file empty! Was there any scanner errors?")
            return None

    def cleanup(self, session_id: str) -> None:
        from docker import errors as docker_errors, from_env as docker_from_env
        logger.info("Cleaning up Naabu artifacts")
        Path(f"{self.report_path}/{session_id}.json").unlink(missing_ok=True)
        client = docker_from_env()
        try:
            container = client.containers.get(f"{self.scanner_name}_{session_id}")
            container.stop(timeout=5)
            container.remove()
        except docker_errors.NotFound:
            logger.warning("Containers could not be found! Skipping cleanup...")
            return

    def spawn_container(self, container_name: str, ctx: ScanContext) -> Container:
        import docker
        logger.info(f"Spawning container: {self.scanner_name}_{container_name}")
        client = docker.from_env()
        return client.containers.run(
            image="projectdiscovery/naabu",
            name=f"{self.scanner_name}_{container_name}",
            command=[
                "-host", ctx.primary_host,
                "-tp", "1000",
                "-silent",
                "-retries", "1",
                "-timeout", "1000",
                "-j",
                "-o", f"/reports/{container_name}.json",
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
