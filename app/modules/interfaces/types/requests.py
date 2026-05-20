from typing import Optional
from pydantic import BaseModel


class ScanRequest(BaseModel):
    url: str
    user_id: int
    config: Optional[dict] = None


class ScheduledScanRequest(BaseModel):
    url: str
    user_id: Optional[int] = None
    codename: str
    job_type: str
    configuration: dict