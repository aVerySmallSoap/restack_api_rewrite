from pathlib import Path
from typing import Optional

from docker.models.containers import Container
from loguru import logger

from app.modules.pipeline.context import DiscoveryContext
from app.modules.scanners.base import IScanner


class HTTPX(IScanner):
    _BASE_REPORT_PATH: str = f"{Path.cwd()}/app/reports/httpx"

    def start_scan(self, session_id: str, ctx: DiscoveryContext) -> dict:
        logger.info(f"Starting HTTPX scan: {session_id}")
        container = self._spawn(session_id, ctx)

        result = container.wait()
        exit_code = result["StatusCode"]

        if exit_code != 0:
            # throw logs and errors
            logger.debug(f"HTTPX exited abruptly! Exit code: {exit_code}")
            container.remove()
            raise RuntimeError(f"HTTPX failed with exit code {exit_code}")
        container.remove()
        return self.parse_results(session_id)

    def parse_results(self, session_id: str) -> dict:
        logger.info(f"Parsing HTTPX results for session: {session_id}")
        with open(f"{self._BASE_REPORT_PATH}/{session_id}.json") as f:
            for line in f.read().splitlines():
                print(line)
        # self._cleanup(session_id)
        pass

    def _cleanup(self, session_id: str) -> None:
        import docker
        logger.info("Cleaning up HTTPX artifacts")
        Path(f"{self._BASE_REPORT_PATH}/{session_id}.json").unlink(missing_ok=True)
        client = docker.from_env()
        try:
            container = client.containers.get(session_id)
            container.stop(timeout=5)
            container.remove()
        except docker.errors.NotFound:
            logger.warning(f"Could not find container with ID: {session_id}. Skipping cleanup")
            pass

    def _spawn(self, container_name: str, ctx: DiscoveryContext) -> Container:
        import docker
        logger.info(f"Spawning container: {container_name}")
        client = docker.from_env()
        client.containers.run(
            image="projectdiscovery/httpx",
            name=container_name,
            command=[
                "-delay", "5s",
                "-pipeline",
                "-http2",
                "-sc",
                "-ct",
                "-server",
                "-td",
                "-method",
                "-ip",
                "-cdn",
                "-probe",
                "-irr",
                "-j",
                "-o", f"/reports/{container_name}.json",
                "-u", ctx.primary_url
            ],
            volumes={
                self._BASE_REPORT_PATH: {
                    "bind": "/reports/",
                    "mode": "rw",
                }
            },
            detach=True,
        )
        return client.containers.get(container_name)