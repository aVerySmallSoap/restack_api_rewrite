import json
from dataclasses import dataclass
from pydantic import BaseModel
from typing import Optional

import redis

redis_client = redis.Redis.from_url(url="redis://localhost:6379")

class TechnologyEntry(BaseModel):
    name: str
    source: str
    version: Optional[str | list[str]] = None
    categories: Optional[list[str]] = None

class TLSFinding(BaseModel):
    host: str
    cwe: str
    issue: str
    severity: str
    detail: Optional[str]

class SiteMap(BaseModel):
    collection: list[dict]
    map: dict[str, dict]

class ScanContext(BaseModel):
    """The default context, in which, contains scan information"""
    session_id: str
    primary_url: str
    primary_host: str
    config: Optional[dict]