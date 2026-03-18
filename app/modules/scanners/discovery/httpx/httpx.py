from typing import Optional

from docker.models.containers import Container

from app.modules.pipeline.context import DiscoveryContext
from app.modules.scanners.base import IScanner


class HTTPX(IScanner):

    def start_scan(self, session_id: str, ctx: DiscoveryContext) -> dict:
        container = self._spawn(session_id, ctx)
        return {}

    def parse_results(self, session_id: str) -> dict:
        self._cleanup(session_id)
        pass

    def _cleanup(self, session_id: str) -> None:
        import docker
        client = docker.from_env()
        client.containers.prune()
        pass

    def _spawn(self, container_name: str, ctx: DiscoveryContext) -> Container:
        import docker
        client = docker.from_env()
        client.containers.run(
            image="projectdiscovery/httpx",
            name=container_name,
        )
        return client.containers.get(container_name)