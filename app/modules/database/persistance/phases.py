"""
Helpers for changing and polling scanning state, as well as, saving different phase states.
"""
from app.modules.interfaces.enums.scan_tracking import ScanPhase
from app.modules.database.database import transaction


def mark_phase_as(report_id: str, phase: ScanPhase):
    with transaction() as db:
        raise NotImplementedError

def poll_phase(report_id: str) -> ScanPhase:
    with transaction() as db:
        raise NotImplementedError

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