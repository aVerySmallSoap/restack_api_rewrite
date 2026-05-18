from typing import Optional

from pydantic import BaseModel


class ScanRequest(BaseModel):
    url: str
    user_id: int
    config: Optional[dict] = None