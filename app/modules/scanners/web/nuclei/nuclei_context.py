from typing import Optional

from pydantic import BaseModel

from app.modules.interfaces.types.options import BaseContext

class NucleiContext(BaseContext):
    pass

class NucleiClassification(BaseModel):
    cve_id: Optional[list] = None
    cwe_id: Optional[list] = None

class NucleiInfo(BaseModel):
    name: str
    tags: list
    severity: str
    classification: Optional[NucleiClassification] = None
    description: Optional[str] = None
    reference: Optional[list | str] = None

class NucleiRecord(BaseContext):
    template: str
    template_id: str
    url: str
    info: NucleiInfo
    matched_at: str
    request: Optional[str] = None
    curl_command: Optional[str] = None