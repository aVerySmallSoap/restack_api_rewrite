from typing import Optional, Any

from app.modules.interfaces.types.context import TechnologyEntry
from app.modules.interfaces.types.options import BaseContext


class DiscoveryContext(BaseContext):
    site_map: Optional[dict] = None
    endpoints: Optional[list[str]] = None
    out_of_scope: Optional[list[str]] = None
    ports: Optional[list[int]] = None
    domains: Optional[dict] = None
    technologies: Optional[list[TechnologyEntry]] = None
    cpes: Optional[list[str]] = None
    queried_vulnerabilities: Optional[list[dict]] = None
    ssl_certs: Optional[dict] = None
