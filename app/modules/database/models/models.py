import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from celery.loaders import default
from sqlalchemy import String, ForeignKey, JSON, Text, Boolean, DateTime, Integer
from sqlalchemy.orm import Mapped, relationship
from sqlalchemy.testing.schema import mapped_column
from sqlalchemy import BigInteger

from app.modules.database.models.base import Base
from app.modules.interfaces.enums.scan_tracking import ScanPhase, ScanProgress
from app.modules.database.models.findings import TechnologiesModel

if TYPE_CHECKING:
    from app.modules.database.models.context import DiscoveryContextModel
    from app.modules.database.models.findings import VulnerabilityModel


class Scan(Base):
    __tablename__ = "scan"

    #Metadata
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    target_url: Mapped[str]
    is_automated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50))

    # filterable data
    scan_date: Mapped[datetime]
    user_id: Mapped[int] = mapped_column(Integer, default=0, nullable=True)

    # relationships
    report: Mapped["ScanReportModel"] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    discovery_context: Mapped["DiscoveryContextModel"] = relationship(
        back_populates="parent",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    vulnerabilities: Mapped[list["VulnerabilityModel"]] = relationship(
        back_populates="parent",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    technologies: Mapped[list["TechnologiesModel"]] = relationship(
        back_populates="parent",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

class ScanResult(Base):
    """
    This stable just contains metadata from the scan reports
    """
    __tablename__ = "scan_result"

    # metadata
    id:Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan.id"))
    scan_duration: Mapped[float]
    user_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    data: Mapped[JSON] = mapped_column(JSON())

class ScanReportModel(Base):
    __tablename__ = "reports"

    # metadata
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan.id"))
    scanner: Mapped[str] = mapped_column(String(50))
    total_vulnerabilities: Mapped[int]
    critical_count: Mapped[int]

    # filterable data
    scan_date: Mapped[datetime]
    scan_type: Mapped[str] = mapped_column(String(50))

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

    # relationships
    scan: Mapped["Scan"] = relationship(
        back_populates="report",
        single_parent=True
    )

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

class UpdateMetadataModel(Base):
    __tablename__ = "update_metadata"

    id: Mapped[str] = mapped_column(primary_key=True)
    tool_name: Mapped[str] = mapped_column(String(75))
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    update_policy_days: Mapped[int] = mapped_column(Integer)