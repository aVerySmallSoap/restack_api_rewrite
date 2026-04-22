import json
from dataclasses import dataclass
from pydantic import BaseModel
from typing import Optional

import redis

redis_client = redis.Redis.from_url(url="redis://localhost:6379")

class TechEntry(BaseModel):
    name: str
    source: str
    version: Optional[str | list[str]] = None
    categories: Optional[list[str]] = None

@dataclass
class TLSFinding:
    host: str
    cwe: str
    issue: str
    severity: str
    detail: Optional[str]

@dataclass
class SiteMap:
    collection: list[dict]
    map: dict[str, dict]

@dataclass
class ScanContext:
    """The default context, in which, contains scan information"""
    session_id: str
    primary_url: str
    primary_host: str
    config: Optional[dict]

    def to_json(self) -> str:
        return json.dumps(self, default=lambda o: o.__dict__)