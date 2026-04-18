import json

from app.modules.tasks.discovery.contexts.preamble_context import PreambleContext
from app.modules.tasks.discovery.contexts.liveliness_context import LivelinessContext
from app.modules.tasks.discovery.contexts.asset_context import AssetContext


class DiscoveryContext:
    preamble_context: PreambleContext
    liveliness_context: LivelinessContext
    asset_context: AssetContext

    def __init__(self, preamble_context = None, liveliness_context = None, asset_context = None):
        self.preamble_context = preamble_context
        self.liveliness_context = liveliness_context
        self.asset_context = asset_context

    def to_json(self) -> str:
        return json.dumps(self, default=lambda o: o.__dict__)