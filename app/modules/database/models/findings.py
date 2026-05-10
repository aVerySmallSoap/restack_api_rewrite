import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import ForeignKey, JSON, String, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.modules.database.models.base import Base

if TYPE_CHECKING:
    from app.modules.database.models.context import DiscoveryContextModel

class TechnologiesModel(Base):
    __tablename__ = "technologies"

    #metadata
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    context_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("discovery_context.id"))

    # data
    name: Mapped[str] = mapped_column(String(150))
    source: Mapped[str] = mapped_column(String(50))
    version: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=True)
    categories: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=True)
    blob: Mapped[JSON] = mapped_column(JSON())

    parent: Mapped["DiscoveryContextModel"]= relationship(
        back_populates="technologies",
        single_parent=True,
    )

class VulnerabilityModel(Base):
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