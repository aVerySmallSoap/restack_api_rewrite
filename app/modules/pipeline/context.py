import json
from dataclasses import dataclass, field
from typing import Optional

import redis

redis_client = redis.Redis.from_url(url="redis://localhost:6379")

@dataclass
class TechEntry:
    name: str
    version: Optional[str]
    source: str # WhatWeb | Wappalyzer-Next | HTTPX
    categories: Optional[list[str]] = None

@dataclass
class BannerEntry:
    host: str
    server: Optional[str]
    powered_by: Optional[str]
    title: Optional[str]
    status_code: int
    redirects_to: Optional[str]

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
class DiscoveryContext:
    session_id: str
    primary_url: str
    primary_host: str
    auth_config: Optional[dict] = None
    site_map: Optional[SiteMap] = None

    # Subfinder + httpx_scanner
    live_hosts: list[str] = field(default_factory=list)

    open_ports: dict[str, list[int]] = field(default_factory=dict)
    # e.g {"example.com: [80,443]}

    # WhatWeb + Wappalyzer + Httpx
    versioned_tech: list[TechEntry] = field(default_factory=list)
    nonversioned_tech: list[TechEntry] = field(default_factory=list)

    # httpx_scanner
    banners: dict[str, BannerEntry] = field(default_factory=dict)

    # SSLyze
    tls_findings: list[TLSFinding] = field(default_factory=list)

    has_https: bool = False

    # derived fields
    nuclei_tags: list[str] = field(default_factory=list)

    cve_map: dict[str, list[str]] = field(default_factory=dict)

    wapiti_scope: str = "domain"

    swagger_url: Optional[str] = None

    # serialization
    def to_json(self) -> str:
        return json.dumps(self, default=lambda o: o.__dict__)

    @classmethod
    def from_redis(cls, session_id: str) -> "DiscoveryContext":
        raw = redis_client.get(f"discovery:{session_id}")
        if not raw:
            raise ValueError(f"No DiscoveryContext found for {session_id}")
        data = json.loads(raw)
        data["versioned_tech"] = [TechEntry(**t) for t in data["versioned_tech"]]
        data["banners"] = {
            k: BannerEntry(**v) for k, v in data["banners"].items()
        }
        data["tls_findings"] = [TLSFinding(**t) for t in data["tls_findings"]]
        return cls(**data)

    def save_to_redis(self, ttl_seconds: int = 86400):
        redis_client.setex(
            f"discovery:{self.session_id}",
            ttl_seconds,
            self.to_json()
        )
