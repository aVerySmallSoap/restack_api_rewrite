import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, ForeignKey, JSON, Text, Boolean, UniqueConstraint
from sqlalchemy.orm import Mapped, relationship, DeclarativeBase
from sqlalchemy.testing.schema import mapped_column
from sqlalchemy import BigInteger

from app.modules.interfaces.enums.scan_tracking import ScanPhase, ScanProgress


class Base(DeclarativeBase):
    pass

# Scan -> Report ( may contain: TechDiscovery and Vulnerabilities )
# Report must rely on Scan ( source of truth ) and not the other way around

class Scan(Base):
    __tablename__ = "scan"

    #Metadata
    id: Mapped[str] = mapped_column(primary_key=True)
    target_url: Mapped[str]
    is_automated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50))

    # filterable data
    scan_date: Mapped[datetime]

    # relationships
    report: Mapped["Report"] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

class ScanResult(Base):
    __tablename__ = "scan_result"

    # metadata
    id:Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan.id"))
    scan_duration: Mapped[float]
    user_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    data: Mapped[JSON] = mapped_column(JSON())

class Report(Base):
    __tablename__ = "reports"

    # metadata
    id: Mapped[str] = mapped_column(primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan.id"))
    scanner: Mapped[str] = mapped_column(String(50))
    total_vulnerabilities: Mapped[int]
    critical_count: Mapped[int]

    # filterable data
    scan_date: Mapped[datetime]
    scan_type: Mapped[str] = mapped_column(String(50))

    # relationships
    scan: Mapped["Scan"] = relationship(
        back_populates="report",
        single_parent=True
    )

    # NEW: Analytics Data
    ai_summary_vulnerabilities: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_summary_tech: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Priority Matrix Quadrants
    high_severity_high_confidence: Mapped[int] = mapped_column(default=0)
    high_severity_low_confidence: Mapped[int] = mapped_column(default=0)
    low_severity_high_confidence: Mapped[int] = mapped_column(default=0)
    low_severity_low_confidence: Mapped[int] = mapped_column(default=0)

    # Summary Statistics
    scanner_agreement_rate: Mapped[Optional[float]] = mapped_column(nullable=True)
    confidence_rate: Mapped[Optional[float]] = mapped_column(nullable=True)
    high_confidence_vulns: Mapped[int] = mapped_column(default=0)
    medium_confidence_vulns: Mapped[int] = mapped_column(default=0)
    low_confidence_vulns: Mapped[int] = mapped_column(default=0)

    tech:Mapped["TechDiscovery"] = relationship(
        back_populates="parent",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

class TechDiscovery(Base):
    __tablename__ = "tech_discovery"

    id: Mapped[str] = mapped_column(primary_key=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("reports.id"))
    scan_date: Mapped[datetime] = mapped_column(String(50))
    data: Mapped[JSON] = mapped_column(JSON())
    parent = relationship("Report", back_populates="tech")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(primary_key=True)
    report_id: Mapped[str] = mapped_column(ForeignKey('reports.id'))
    scan_date: Mapped[datetime]
    scanner: Mapped[str] = mapped_column(String(50))
    vulnerability_type: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(50))
    confidence: Mapped[str] = mapped_column(String(25))
    http_request: Mapped[Optional[JSON]] = mapped_column(JSON(), nullable=True)
    description: Mapped[str]
    endpoint: Mapped[str]
    remediation_effort: Mapped[str]
    method: Mapped[str]
    state: Mapped[str]
    data: Mapped[JSON] = mapped_column(JSON())

class ScheduledScans(Base):
    __tablename__ = "scheduled_scans"

    id: Mapped[str] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(String())
    user_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    codename: Mapped[str] = mapped_column(String(), unique=True)
    job_type: Mapped[str] = mapped_column(String())
    configuration: Mapped[JSON] = mapped_column(JSON())

class ScanPhaseProgress(Base):
    __tablename__ = "scan_progress"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[str] = mapped_column(ForeignKey('scan.id'))
    phase: Mapped[ScanPhase] = mapped_column(String(50))
    progress: Mapped[ScanProgress] = mapped_column(String(50))
    has_errored: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

# class Configuration(Base):
#     pass