"""
Helpers for changing and polling scanning state, as well as, saving different phase states.
"""
from app.modules.interfaces.enums.scan_tracking import ScanPhase, ScanProgress
from app.modules.database.database import transaction
from app.modules.database.models.models import ScanPhaseProgress


def mark_phase_as(
        report_id: str,
        phase: ScanPhase,
        progress: ScanProgress = ScanProgress.IN_PROGRESS
):
    with transaction() as db:
        tracker = db.query(ScanPhaseProgress).filter(ScanPhaseProgress.scan_id == report_id).first()
        if tracker:
            tracker.phase = phase
            db.add(tracker)
        else:
            tracker = ScanPhaseProgress(
                scan_id=report_id,
                phase=phase,
                progress=progress,
            )
            db.add(tracker)

def mark_phase_as_errored(report_id: str, phase: ScanPhase):
    with transaction() as db:
        tracker = db.query(ScanPhaseProgress).filter(ScanPhaseProgress.scan_id == report_id).first()
        if tracker is None:
            tracker = ScanPhaseProgress(
                scan_id=report_id,
                phase=phase,
                progress=ScanProgress.ERROR,
                has_errored=True
            )
            db.add(tracker)
        else:
            tracker.phase = phase
            tracker.has_errored = True
            tracker.progress = ScanProgress.ERROR
            db.add(tracker)

def mark_as_complete(report_id: str, phase: ScanPhase):
    with transaction() as db:
        tracker = db.query(ScanPhaseProgress).filter(ScanPhaseProgress.scan_id == report_id).first()
        if tracker is None:
            tracker = ScanPhaseProgress(
                scan_id=report_id,
                phase=phase,
                progress=ScanProgress.SUCCESS,
                has_errored=False
            )
            db.add(tracker)
        else:
            tracker.progress = ScanProgress.ERROR
            db.add(tracker)

def poll_phase(report_id: str) -> ScanPhase:
    with transaction() as db:
        return db.query(ScanPhaseProgress).filter(ScanPhaseProgress.scan_id == report_id).first().phase

def save_preamble_phase():
    raise NotImplementedError

def save_liveliness_phase():
    raise NotImplementedError

def save_query_vuln_phase():
    raise NotImplementedError

def save_attack_phase():
    raise NotImplementedError

def save_report_phase():
    raise NotImplementedError

def save_analytics_phase():
    raise NotImplementedError