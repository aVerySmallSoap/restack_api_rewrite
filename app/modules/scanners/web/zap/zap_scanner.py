from modules.interfaces.base import IScanner
from modules.interfaces.options import BaseContext

# This class might communicate with containers, but the class itself does not spawn them
class ZapScanner(IScanner):


    def start_scan(self, session_id: str, ctx: BaseContext) -> dict:
        pass

    def parse_results(self, session_id: str) -> dict:
        pass

    def _cleanup(self, session_id: str) -> None:
        pass