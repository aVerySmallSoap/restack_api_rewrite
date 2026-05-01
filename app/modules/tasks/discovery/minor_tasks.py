import json

from billiard import TimeLimitExceeded

from app.modules.interfaces.types.context import ScanContext
from app.services.celery_app import celery_app
from app.modules.scanners.discovery.search_vulns.search_vulns_query import SearchVulnsQuery
from app.modules.interfaces.types.options import ScannerTaskResult


@celery_app.task(bind=True)
def task_search_vuln_query(self, results: list[dict],  session_id: str, ctx: str) -> dict:
    try:
        scan_context = ScanContext(**json.loads(ctx))
        return {"type": "search_vulns", "result": SearchVulnsQuery().start_scan(session_id, scan_context)}
    except TimeLimitExceeded:
        return ScannerTaskResult(
            scanner="whatweb",
            phase="asset",
            status="timeout",
            result=None,
            error="Celery time limit exceeded",
            runtime_ms=300
        ).model_dump()
