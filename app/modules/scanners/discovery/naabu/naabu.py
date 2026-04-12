from pathlib import Path

from docker.models.containers import Container
from loguru import logger

from app.modules.interfaces.options import BaseContext
from app.modules.interfaces.base import IContainerScanner
from app.modules.pipeline.context import DiscoveryContext


class Naabu(IContainerScanner):
    _base_report_path = f"{Path.cwd()}/app/reports/naabu"
    _prefix = "naabu"
    _scanner_context = None

    def start_scan(self, session_id: str, ctx: DiscoveryContext) -> dict:
        logger.info(f"Starting Naabu scan: {session_id}")
        container = self._spawn(session_id, ctx)
        # self._scanner_context.session_id = session_id

        result = container.wait()
        exit_code = result["StatusCode"]

        if exit_code != 0:
            # throw logs and errors
            logger.debug(f"Naabu exited abruptly! Exit code: {exit_code}")
            # container.remove()
            raise RuntimeError(f"Naabu failed with exit code {exit_code}")
        # container.remove()
        return self._parse_results(session_id)

    def _parse_results(self, session_id: str) -> dict:
        pass

    def _cleanup(self, session_id: str) -> None:
        pass

    def _spawn(self, container_name: str, ctx: DiscoveryContext) -> Container:
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
