"""
Helpers for CRUD operations regarding scans.
"""
from datetime import datetime
from app.modules.database.database import transaction
from app.modules.database.models import Scan
from app.modules.interfaces.enums.scan_tracking import ScanTypes


def create_scan(
        session_id: str,
        scan_date: datetime,
        target: str,
        is_automated: bool,
        scan_type: ScanTypes
) -> Scan:
    with transaction() as db:
        scan = Scan(
            id=session_id,
            scan_date=scan_date,
            target_url=target,
            is_automated=is_automated,
            scan_type=scan_type
        )
        db.add(scan)
        return scan

def retrieve_scan(session_id: str) -> Scan | None:
    with transaction() as db:
        return db.query(Scan).filter(Scan.id == session_id).first()

def update_scan(
        session_id: str,
        scan_date: datetime,
        target: str,
        is_automated: bool,
        scan_type: ScanTypes
) -> Scan:
    with transaction() as db:
        scan = db.query(Scan).filter(Scan.id == session_id).first()
        if not scan:
            raise ValueError(f"Scan with id {session_id} not found")
        scan.scan_date = scan_date
        scan.target_url = target
        scan.is_automated = is_automated
        scan.scan_type = scan_type
        db.add(scan)
        return scan

def delete_scan(session_id: str) -> None:
    with transaction() as db:
        scan = db.query(Scan).filter(Scan.id == session_id).first()
        if not scan:
            raise ValueError(f"Scan with id {session_id} not found")
        db.delete(scan)