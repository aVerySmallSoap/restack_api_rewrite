from pathlib import Path

from loguru import logger
from docker.models.containers import Container

from app.modules.pipeline.context import ScanContext
from app.modules.interfaces.base import IHeadlessScanner
from app.modules.pipeline.context import TechEntry


class WappalyzerNext(IHeadlessScanner):
    _base_report_path = f"{Path.cwd()}/app/reports/wappalyzer_next"
    _prefix = "wappalyzer-next"
    _prefix_headless = "wappalyzer-next_headless"
    _scanner_context: ScanContext

    def start_scan(self, session_id: str, ctx: ScanContext) -> dict:
        logger.info(f"Starting Wappalyzer Next scan: {session_id}")
        self._scanner_context = ctx
        container = self._spawn(session_id, ctx)
        headless_container = self._spawn_headless(session_id, ctx)

        result = container.wait()
        headless_result = headless_container.wait()

        if result.get("StatusCode") != 0:
            logger.error(f"Wappalyzer-next has exited abruptly on exit code: {result.get('StatusCode')}")
            container.remove()
            raise
        if headless_result.get("StatusCode") != 0: # crash
            logger.error(f"Headless Wappalyzer-next has exited abruptly on exit code: {result.get('StatusCode')}")
            headless_container.remove()
            raise
        return self._parse_results(session_id)

    def _parse_results(self, session_id: str) -> dict:
        import json
        logger.info(f"Parsing wappalyzer-next results for session: {session_id}")
        collection: list[str] = []
        with open(f"{self._base_report_path}/{session_id}.json") as f:
            if f.tell() != 0:
                for line in f.read().splitlines():
                    record = json.loads(line).get(self._scanner_context.primary_url)
                    if record is not None or record != {}:
                        assert isinstance(record, dict)
                        for plugin, content in record:
                            print(f"{plugin}: {content["version"] if content["version"] != "" else None}")
                            collection.append(
                                TechEntry(
                                    name=plugin,
                                    version=content["version"] if content["version"] != "" else None,
                                    source="wappalyzer-next",
                                    categories=None
                                ).model_dump_json()
                            )
        with open(f"{self._base_report_path}/{self._prefix_headless}_{session_id}.json") as f:
            if f.tell() != 0:
                for line in f.read().splitlines():
                    record = json.loads(line).get(self._scanner_context.primary_url)
                    if record is not None or record != {}:
                        assert isinstance(record, dict)
                        for plugin, content in record:
                            collection.append(
                                TechEntry(
                                    name=plugin,
                                    version=content["version"] if content["version"] != "" else None,
                                    source="wappalyzer-next",
                                    categories=None
                                ).model_dump_json()
                            )
        self._cleanup(session_id)
        return {"data": collection}

    def _cleanup(self, session_id: str) -> None:
        import docker
        logger.info("Cleaning up wappalyzer-next artifacts")
        Path(f"{self._base_report_path}/{session_id}.json").unlink(missing_ok=True) #TODO: might error out if a scan produces no files
        client = docker.from_env()
        try:
            container = client.containers.get(f"{self._prefix}_{session_id}")
            container.stop(timeout=5)
            container.remove()
            container = client.containers.get(f"{self._prefix_headless}_{session_id}")
            container.stop(timeout=5)
            container.remove()
        except docker.errors.NotFound:
            logger.warning(f"Could not find container with ID: {self._prefix}_{session_id}. Skipping cleanup")

    def _spawn(self, container_name: str, ctx: ScanContext) -> Container:
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

    def _spawn_headless(self, container_name, ctx: ScanContext) -> Container:
        import docker
        logger.info(f"Spawning container: {self._prefix_headless}_{container_name}")
        client = docker.from_env()
        return client.containers.run(
            image="localhost/wappalyzer",
            name=f"{self._prefix_headless}_{container_name}",
            command=[
                "--scan-type", "full",
                "-oJ", f"/reports/{self._prefix_headless}_{container_name}.json",
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