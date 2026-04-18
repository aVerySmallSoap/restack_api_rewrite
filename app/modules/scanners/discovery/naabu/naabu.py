import json
from pathlib import Path

import docker
from docker.models.containers import Container
from loguru import logger

from app.modules.interfaces.base import IContainerScanner
from app.modules.pipeline.context import ScanContext


class Naabu(IContainerScanner):
    _base_report_path = f"{Path.cwd()}/app/reports/naabu"
    _prefix = "naabu"
    _scanner_context = None

    def start_scan(self, session_id: str, ctx: ScanContext) -> dict:
        logger.info(f"Starting Naabu scan: {session_id}")
        container = self._spawn(session_id, ctx)
        # self._scanner_context.session_id = session_id
        result = container.wait()
        exit_code = result.get("StatusCode")

        if exit_code != 0:
            # throw logs and errors
            logger.error(f"Naabu has exited abruptly on exit code: {result.get('StatusCode')}")
            raise
        return self._parse_results(session_id)

    def _parse_results(self, session_id: str) -> dict:
        logger.info(f"Parsing Naabu results for session: {session_id}")
        ports: list[int] = []
        with open(f"{self._base_report_path}/{session_id}.json") as f:
            for line in f.read().splitlines():
                record = json.loads(line) # TODO: also check if the ip is the same
                ports.append(record["port"])
        self._cleanup(session_id)
        return {"ports": ports}

    def _cleanup(self, session_id: str) -> None:
        logger.info("Cleaning up Naabu artifacts")
        Path(f"{self._base_report_path}/{session_id}.json").unlink(missing_ok=True)
        client = docker.from_env()
        try:
            container = client.containers.get(f"{self._prefix}_{session_id}")
            container.stop(timeout=5)
            container.remove()
        except docker.errors.NotFound:
            logger.warning("Containers could not be found! Skipping cleanup...")
            return

    def _spawn(self, container_name: str, ctx: ScanContext) -> Container:
        import docker
        logger.info(f"Spawning container: {self._prefix}_{container_name}")
        client = docker.from_env()
        return client.containers.run(
            image="projectdiscovery/naabu",
            name=f"{self._prefix}_{container_name}",
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
                self._base_report_path: {
                    "bind": "/reports/",
                    "mode": "rw",
                }
            },
            detach=True,
            auto_remove=False,
        )
