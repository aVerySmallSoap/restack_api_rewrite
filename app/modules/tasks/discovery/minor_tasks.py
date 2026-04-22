import json

from app.modules.pipeline.context import ScanContext
from app.modules.celery_app import celery_app
from app.modules.scanners.discovery.search_vulns.search_vulns_query import SearchVulnsQuery

@celery_app.task(bind=True)
def task_search_vuln_query(self, results: list[dict],  session_id: str, ctx: str) -> dict:
    scan_context = ScanContext(**json.loads(ctx))
    return {"type": "search_vulns", "result": SearchVulnsQuery().start_scan(session_id, scan_context)}