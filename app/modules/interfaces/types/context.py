import uuid
from datetime import datetime

from pydantic import BaseModel
from typing import Optional

import redis

redis_client = redis.Redis.from_url(url="redis://localhost:6379")

class TechnologyEntry(BaseModel):
    name: str
    source: str
    version: Optional[str | list[str]] = None
    categories: Optional[list[str]] = None

class UpdateMetaData(BaseModel):
    """
    Contains the metadata about tooling updates.
    This should determine whether to update the tool or not.
    """
    id: uuid.UUID
    tool_name: str
    updated_at: datetime
    update_policy_days: int

class ScanContext(BaseModel):
    """The default context, in which, contains scan information"""
    session_id: str
    primary_url: str
    primary_host: str
    config: Optional[dict]