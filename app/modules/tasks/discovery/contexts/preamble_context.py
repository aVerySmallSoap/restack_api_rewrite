from typing import Optional

from app.modules.interfaces.options import PhaseContext

class PreambleContext(PhaseContext):
    site_map: dict
    endpoints: list[str]
    out_of_scope: list[str]
    ports: list[int]
    domains: Optional[list[str]] = None
