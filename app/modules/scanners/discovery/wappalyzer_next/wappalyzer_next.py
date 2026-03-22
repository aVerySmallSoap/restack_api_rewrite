from pathlib import Path

from loguru import logger
from docker.models.containers import Container

from app.modules.pipeline.context import DiscoveryContext
from app.modules.interfaces.base import IScanner
from app.modules.interfaces.options import WappalyzerContext


class WappalyzerNext(IScanner):
    _base_report_path: str = f"{Path.cwd()}/app/reports/wappalyzer_next"
    _prefix = "wappalyzer-next"
    _scanner_context = WappalyzerContext()

    def start_scan(self, session_id: str, ctx: DiscoveryContext) -> dict:
        logger.info(f"Starting Wappalyzer Next scan: {session_id}")
        container = self._spawn(session_id, ctx)

        result = container.wait()
        exit_code = result["StatusCode"]

        if exit_code != 0:
            logger.debug(f"Wappalyzer exited abruptly! Exit code: {exit_code}")
            container.remove()
            raise RuntimeError(f"WappalyzerNext failed with exit code {exit_code}")
        container.remove()
        return self.parse_results(session_id)

    def parse_results(self, session_id: str) -> dict:
        import json
        logger.info(f"Parsing wappalyzer-next results for session: {session_id}")
        collection = {}
        with open(f"{self._base_report_path}/{session_id}.json") as f:
            for line in f.read().splitlines():
                collection.update(json.loads(line))
        self._scanner_context.content = collection
        return self._scanner_context.content

    def _cleanup(self, session_id: str) -> None:
        import docker
        logger.info("Cleaning up wappalyzer-next artifacts")
        Path(f"{self._base_report_path}/{session_id}.json").unlink(missing_ok=True) #TODO: might error out if a scan produces no files
        client = docker.from_env()
        try:
            container = client.containers.get(f"{self._prefix}_{session_id}")
            container.stop(timeout=5)
            container.remove()
        except docker.errors.NotFound:
            logger.warning(f"Could not find container with ID: {self._prefix}_{session_id}. Skipping cleanup")
            pass

    def _spawn(self, container_name: str, ctx: DiscoveryContext) -> Container:
        import docker
        logger.info(f"Spawning container: {self._prefix}_{container_name}")
        client = docker.from_env()
        return client.containers.run(
            image="localhost/wappalyzer",
            name=f"{self._prefix}_{container_name}",
            command=[
                "--scan-type", "balanced",
                "-oJ", f"/reports/{container_name}.json",
                "-i", ctx.primary_url
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