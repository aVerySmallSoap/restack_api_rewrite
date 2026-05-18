import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, JSON, String, Integer
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.modules.database.models.base import Base

if TYPE_CHECKING:
    from app.modules.database.models.models import Scan


class DiscoveryContextModel(Base):
    __tablename__ = 'discovery_context'

    #metadata
    id:Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id:Mapped[uuid.UUID] = mapped_column(ForeignKey('scan.id'))

    #data
    site_map: Mapped[JSON] = mapped_column(JSON())
    endpoints: Mapped[list[str]] = mapped_column(ARRAY(String))
    out_of_scope: Mapped[list[str]] = mapped_column(ARRAY(String))
    ports: Mapped[list[str]] = mapped_column(ARRAY(Integer))
    domains: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=True)
    cpes: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=True)
    queried_vulnerabilities: Mapped[list[JSON]] = mapped_column(ARRAY(JSON), nullable=True)
    ssl_certs: Mapped[JSON] = mapped_column(JSON(), nullable=True)

    #relationships
    parent: Mapped["Scan"] = relationship(
        back_populates="discovery_context",
        single_parent=True,
    )