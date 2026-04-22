from typing import Optional

from app.modules.scanners.web.wapiti.wapiti_config_builder import WapitiConfig


class WapitiContext:
    config: Optional[WapitiConfig] = None
    is_headless: Optional[bool] = None