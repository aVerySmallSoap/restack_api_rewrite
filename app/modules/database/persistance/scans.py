"""
Helpers for CRUD operations regarding scans.
"""
from datetime import datetime
from app.modules.database.database import transaction
from app.modules.database.models import Scan


def create_scan(session_id: str, scan_date: datetime) -> Scan:
    with transaction() as db:
        scan = Scan(
            id=session_id,
            scan_date=scan_date
        )
        raise NotImplementedError

def retrieve_scan(session_id: str) -> Scan | None:
    raise NotImplementedError

def update_scan(session_id: str) -> datetime:
    raise NotImplementedError

def delete_scan(session_id: str) -> None:
    raise NotImplementedError