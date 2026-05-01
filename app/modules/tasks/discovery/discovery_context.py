from typing import Optional

from app.modules.interfaces.types.context import TechEntry
from app.modules.interfaces.types.options import BaseContext


class DiscoveryContext(BaseContext):
    site_map: Optional[dict] = None
    endpoints: Optional[list[str]] = None
    out_of_scope: Optional[list[str]] = None
    ports: Optional[list[int]] = None
    domains: Optional[dict] = None
    technologies: Optional[list[TechEntry]] = None
    cpes: Optional[list[str]] = None
    queried_vulnerabilities: Optional[list[dict]] = None
