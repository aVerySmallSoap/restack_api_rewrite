from app.modules.interfaces.base import IConfigBuilder
from app.modules.interfaces.enums.wapiti.wapiti_enums import WapitiFlag, WapitiFlagDefinition

FLAG_REGISTRY: dict[WapitiFlag, WapitiFlagDefinition] = {
    WapitiFlag.SCOPE: WapitiFlagDefinition("--scope", True),
    WapitiFlag.MODULES: WapitiFlagDefinition("--modules", True),

}


class WapitiConfigBuilder(IConfigBuilder):
    """Builds the configuration for Wapiti."""
    _default_commands = []


    def build(self) -> list:
        return []