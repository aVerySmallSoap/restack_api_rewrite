import json
from pathlib import Path

from docker.models.containers import Container
from loguru import logger

from app.modules.pipeline.context import DiscoveryContext
from app.modules.interfaces.base import IContainerScanner
from app.modules.interfaces.options import SubfinderContext


class Subfinder(IContainerScanner):
    _base_report_path: str = f"{Path.cwd()}/app/reports/subfinder"
    _prefix: str = "subfinder"
    _scanner_context: SubfinderContext

    def __init__(self):
        self._scanner_context = SubfinderContext()

    def start_scan(self, session_id: str, ctx: DiscoveryContext) -> dict:
        logger.info(f"Starting Subfinder scan: {session_id}")
        container = self._spawn(session_id, ctx)
        self._scanner_context.session_id = session_id

        result = container.wait()
        exit_code = result.get("StatusCode")

        if exit_code != 0:
            logger.error(f"Subfinder has exited abruptly on exit code: {result.get('StatusCode')}")
            container.remove()
            raise
        return self._parse_results(session_id)

    def _parse_results(self, session_id: str) -> dict:
        logger.info(f"Parsing Subfinder results for session: {session_id}")
        with open(f"{self._base_report_path}/{session_id}.json") as f:
            if f.tell() == 0:
                return self._scanner_context.content
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
        self._scanner_context.content = {
            base_input: {
                "hosts": hosts,
                "sources": list(sources)
            }
        }
        self._cleanup(session_id)
        return self._scanner_context.content

    def _cleanup(self, session_id: str) -> None:
        import docker
        logger.info("Cleaning up Subfinder artifacts")
        Path(f"{self._base_report_path}/{session_id}.json").unlink(missing_ok=True)
        client = docker.from_env()
        try:
            container = client.containers.get(f"{self._prefix}_{session_id}")
            container.stop(timeout=5)
            container.remove()
        except docker.errors.NotFound:
            logger.warning(f"Could not find container with ID: subfinder_{session_id}. Skipping cleanup")

    def _spawn(self, container_name: str, ctx: DiscoveryContext) -> Container:
        import docker
        logger.info(f"Spawning container: {self._prefix}_{container_name}")
        client = docker.from_env()
        return client.containers.run(
            image="projectdiscovery/subfinder",
            name=f"{self._prefix}_{container_name}",
            command=[
                "-all",
                "-cs",
                "-oJ",
                "-o", f"/reports/{container_name}.json",
                "-d", ctx.primary_url
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