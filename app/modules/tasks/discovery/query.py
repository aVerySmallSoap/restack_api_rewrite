import json

from billiard import TimeLimitExceeded
from loguru import logger

from app.modules.interfaces.types.context import ScanContext, redis_client
from app.services.celery_app import celery_app
from app.modules.scanners.discovery.search_vulns.search_vulns_query import SearchVulnsQuery
from app.modules.interfaces.types.options import ScannerTaskResult
from app.modules.database.database import transaction
from app.modules.database.persistance.phases import mark_phase_as_errored, mark_as_complete
from app.modules.interfaces.enums.scan_tracking import ScanPhase
from app.modules.database.models.context import DiscoveryContextModel
from app.modules.tasks.discovery.discovery_context import DiscoveryContext
from app.modules.database.models.findings import TechnologiesModel


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

@celery_app.task(bind=True)
def task_quick_scan_end(self, results: list[dict], session_id: str, ctx: str) -> dict:
    try:
        raw = redis_client.get(f"discovery:{session_id}")
        if raw is None:
            raise ValueError(f"Missing discovery context for session {session_id}")
        discovery_ctx:DiscoveryContext = DiscoveryContext.model_validate_json(raw)

        with transaction() as db:
            db.add(
                DiscoveryContextModel(
                    scan_id=session_id,
                    site_map=discovery_ctx.site_map,
                    endpoints=discovery_ctx.endpoints,
                    out_of_scope=discovery_ctx.out_of_scope,
                    ports=discovery_ctx.ports,
                    domains=discovery_ctx.domains,
                    cpes=discovery_ctx.cpes,
                    queried_vulnerabilities=discovery_ctx.queried_vulnerabilities,
                    ssl_certs=discovery_ctx.ssl_certs,
                )
            )

            if discovery_ctx.technologies:
                tech_list = []
                for tech in discovery_ctx.technologies:
                    tech_list.append(
                        TechnologiesModel(
                            scan_id=session_id,
                            name=tech.name,
                            source=tech.source,
                            version=tech.version,
                            categories=tech.categories,
                            blob= tech.model_dump(mode="json")
                        )
                    )
                db.add_all(tech_list)

        mark_as_complete(
            report_id=session_id,
            phase=ScanPhase.VULN_QUERY
        )
    except Exception as e:
        logger.exception(e)
        mark_phase_as_errored(
            report_id=session_id,
            phase=ScanPhase.ATTACK,
        )
        raise