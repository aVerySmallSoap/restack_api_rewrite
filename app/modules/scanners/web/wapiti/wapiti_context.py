from typing import Optional

from app.modules.interfaces.options import ContentableContext
from app.modules.scanners.web.wapiti.wapiti_config_builder import WapitiConfig


class WapitiContext(ContentableContext):
    config: Optional[WapitiConfig] = None
    is_headless: Optional[bool] = None