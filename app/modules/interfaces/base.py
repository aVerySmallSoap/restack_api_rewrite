from abc import ABC, abstractmethod

from docker.models.containers import Container

from app.modules.pipeline.context import DiscoveryContext


class IScanner(ABC):

    @abstractmethod
    def start_scan(self, session_id: str, ctx: DiscoveryContext) -> dict:
        pass

    @abstractmethod
    def parse_results(self, session_id: str) -> dict:
        pass

    @abstractmethod
    def _cleanup(self, session_id: str) -> None:
        """Cleans up any temporary files and containers. Always should be run at the end of parse_results"""
        pass

    @abstractmethod
    def _spawn(self, container_name: str, ctx: DiscoveryContext) -> Container:
        """Spawns and runs a docker container associated with the scanner"""
        pass