from app.modules.interfaces.base import IConfigBuilder

class WapitiConfigBuilder(IConfigBuilder):
    """Builds the configuration for Wapiti."""
    _default_commands = []


    def build(self) -> list:
        return []