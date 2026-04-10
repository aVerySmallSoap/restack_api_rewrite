from pathlib import Path

from docker.models.containers import Container
from loguru import logger

from app.modules.interfaces.base import IHeadlessScanner
from app.modules.interfaces.options import BaseContext
from app.modules.pipeline.context import DiscoveryContext
from app.modules.scanners.web.nuclei.nuclei_context import NucleiContext


class Nuclei(IHeadlessScanner):
    _base_report_path = f"{Path.cwd()}/app/reports/nuclei"
    _prefix = "nuclei"
    _prefix_headless = "nuclei_headless"
    _scanner_context: NucleiContext

    def __init__(self):
        self._scanner_context = NucleiContext()

    def start_scan(self, session_id: str, ctx: DiscoveryContext) -> dict:
        #Check if there is a headless flag
        logger.info(f"Starting Nuclei scan: {session_id}")
        container = self._spawn(session_id, ctx)
        result = container.wait()

        if result.get("StatusCode") != 0:
            logger.error(
                f"Katana container: {container.name} has exited abruptly!")
            raise RuntimeError(f"Katana container: {container.name} exited abruptly!")
        return self.parse_results(session_id)

    def parse_results(self, session_id: str) -> dict:
        # TODO: implement
        pass

    def _cleanup(self, session_id: str) -> None:
        # TODO: implement
        pass

    def _spawn(self, container_name: str, ctx: DiscoveryContext) -> Container:
        import docker
        logger.info(f"Spawning container: {self._prefix}_{container_name}")
        client = docker.from_env()
        return client.containers.run(
            image="projectdiscovery/nuclei",
            name=f"{self._prefix}_{container_name}",
            command=[
                "-u", ctx.primary_url,
                "-v",
                "-j",
                "-o", f"/reports/{self._prefix}_{container_name}.json",
                "-etags", "wp-plugin"
                "-fhr",
                # "-dast", # Dast should be a separate task in celery
                "-duc" # Templates are updated before the server starts
            ],
            volumes={
                self._base_report_path: {
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

    def _spawn_headless(self, container_name: str, ctx: BaseContext) -> Container:
        import docker
        logger.info(f"Spawning container: {self._prefix_headless}_{container_name}")
        client = docker.from_env()
        return client.containers.run(
            image="projectdiscovery/nuclei",
            name=f"{self._prefix_headless}_{container_name}",
            command=[],
            volumes={
                self._base_report_path: {
                    "bind": "/reports/",
                    "mode": "rw",
                }
            },
            detach=True,
            auto_remove=False,
        )