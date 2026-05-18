from datetime import datetime
from typing import Optional, Any

from pydantic import BaseModel


# SARIF
class SARIFRule(BaseModel):
    id: str
    name: str
    short_description_text: Optional[str] = None
    full_description_text: Optional[str] = None
    help_text: Optional[str | list] = None
    help_markdown: Optional[str | dict] = None
    properties: Optional[dict] = None # This could be a nightmare to debug
    level: str

class SARIFResult(BaseModel):
    rule_id: str
    message_text: str
    location: str
    properties: Optional[dict] = None

class SARIFTool(BaseModel):
    name: str
    rules: Optional[list[SARIFRule]] = None

class SARIF(BaseModel):
    version: str = "2.1.0"
    runs: Optional[list[SARIFTool]] = None

# Normalization
class Vulnerability(BaseModel):
    # TODO: There is a severe mismatch between this model and VulnerabilityModel
    name: str
    severity: str
    description: str
    solution: str
    cwe_id: str
    links: Optional[str | dict] = None
    sources: Optional[list[str]] = None
    location: Optional[str] = None
    fingerprint: Optional[str] = None

# SSLyze Types

class SSLyzeCertificateRecord(BaseModel):
    subject: str
    key_algorithm: str
    key_size: int
    expires_at: datetime
    severity: str
    reason: str

class SSLyzeTLSRecord(BaseModel):
    severity: str
    protocol: str
    reason: str

class SSLyzeRecord(BaseModel):
    target: str
    port: int
    ip_address: str
    highest_tls: str
    supported_protocols: list[str]
    certificate_findings: list[SSLyzeCertificateRecord]
    tls_findings: list[dict]