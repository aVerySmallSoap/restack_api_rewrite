from abc import ABC, abstractmethod

from docker.models.containers import Container

from app.modules.pipeline.context import DiscoveryContext
from app.modules.interfaces.options import BaseContext


class IScanner(ABC):
    @property
    @abstractmethod
    def _base_report_path(self) -> str:
        pass

    @property
    @abstractmethod
    def _prefix(self) -> str:
        pass

    @property
    @abstractmethod
    def _scanner_context(self) -> BaseContext:
        pass

    @abstractmethod
    def start_scan(self, session_id: str, ctx: DiscoveryContext) -> BaseContext:
        pass

    @abstractmethod
    def parse_results(self, session_id: str) -> BaseContext:
        pass

    @abstractmethod
    def _cleanup(self, session_id: str) -> None:
        """Cleans up any temporary files and containers. Always should be run at the end of parse_results"""
        pass

    @abstractmethod
    def _spawn(self, container_name: str, ctx: DiscoveryContext) -> Container:
        """Spawns and runs a docker container associated with the scanner"""
        pass