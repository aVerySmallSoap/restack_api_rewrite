import json
from datetime import datetime
from typing import Optional, Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class VulnerabilitiesModelDTO(BaseModel):
    id: UUID
    scan_id: UUID
    scan_date: datetime
    scanner: str
    vulnerability_type: str
    severity: str
    confidence: str
    description: str
    endpoint: str
    remediation_effort: str
    blob: Optional[dict] = None

    method: Optional[str] = None
    state: Optional[str] = None
    http_request: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class TechnologiesModelDTO(BaseModel):
    id: UUID
    scan_id: UUID

    name: str
    source: str
    version: Optional[list[str]] = None
    categories: Optional[list[str]] = None
    blob: Optional[dict] = None

    model_config = ConfigDict(from_attributes=True)


class DiscoveryContextDTO(BaseModel):
    id: UUID
    scan_id: UUID

    site_map: Optional[dict] = None
    endpoints: Optional[list[str]] = None
    out_of_scope: Optional[list[str]] = None
    ports: Optional[list[int]] = None
    domains: Optional[list] = None
    cpes: Optional[list[str]] = None
    queried_vulnerabilities: Optional[list[dict]] = None
    ssl_certs: Optional[dict] = None

    model_config = ConfigDict(from_attributes=True)

    @field_validator("ssl_certs", mode="before")
    @classmethod
    def parse_ssl_certs(cls, v: Any) -> Any:
        """
        ssl_certs is sometimes double-encoded: the JSON column stores a
        JSON string instead of a JSON object, so SQLAlchemy hands us a str.
        Decode it here so Pydantic always sees a dict (or None).
        """
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                return parsed if isinstance(parsed, dict) else None
            except (json.JSONDecodeError, ValueError):
                return None
        return v


class ScanReportModelDTO(BaseModel):
    id: UUID
    scan_id: UUID
    scanner: str
    total_vulnerabilities: int
    critical_count: int

    scan_date: datetime
    scan_type: str

    ai_summary_vulnerabilities: Optional[str] = None
    ai_summary_tech: Optional[str] = None

    high_severity_high_confidence: int
    high_severity_low_confidence: int
    low_severity_high_confidence: int
    low_severity_low_confidence: int

    scanner_agreement_rate: Optional[float] = None
    confidence_rate: Optional[float] = None
    high_confidence_vulns: int
    medium_confidence_vulns: int
    low_confidence_vulns: int

    model_config = ConfigDict(from_attributes=True)


class ScanDTO(BaseModel):
    id: UUID
    target_url: str
    is_automated: bool
    scan_type: str
    scan_date: datetime
    user_id: Optional[int] = None
    total_vulnerabilities: Optional[int] = 0
    critical_count: Optional[int] = 0

    report: Optional[ScanReportModelDTO] = None
    discovery_context: Optional[DiscoveryContextDTO] = None
    vulnerabilities: list[VulnerabilitiesModelDTO] = Field(default_factory=list)
    technologies: list[TechnologiesModelDTO] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class ScanTableDTO(BaseModel):
    id: UUID
    target_url: str
    is_automated: bool
    scan_type: str
    scan_date: datetime
    user_id: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)