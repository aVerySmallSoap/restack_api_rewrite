from typing import Optional

from app.modules.interfaces.types.options import BaseContext
from app.modules.tasks.discovery.discovery_context import DiscoveryContext
from app.modules.scanners.web.nuclei.nuclei_context import NucleiRecord


class AttackContext(BaseContext):
    discovery_context: DiscoveryContext
    nuclei_result: Optional[dict] = None
    wapiti_result: Optional[dict] = None
    zap_result: Optional[dict] = None
