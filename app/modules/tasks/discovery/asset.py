import json
import uuid

from billiard import TimeLimitExceeded
from loguru import logger

from app.services.celery_app import celery_app
from app.modules.interfaces.types.context import ScanContext, redis_client
from app.modules.scanners.discovery import (
    SSLyze, WhatWeb, WappalyzerNext
)
from app.modules.tasks.discovery.discovery_context import DiscoveryContext
from app.modules.utils.utils import tech_to_cpe, resolve_tech_to_tech_entry
from app.modules.interfaces.types.options import ScannerTaskResult
from app.modules.database.persistance.phases import mark_phase_as_errored, mark_phase_as
from app.modules.interfaces.enums.scan_tracking import ScanPhase
from app.modules.database.models.context import DiscoveryContextModel
from app.modules.database.database import transaction


@celery_app.task(
    bind=True,
    soft_time_limit=240,
    time_limit=300,
)
def task_sslyze(self, liveliness_ctx: str, session_id: str, ctx_json: str) -> dict:
    try:
        ctx = ScanContext(**json.loads(ctx_json))
        return {"type": "sslyze", "result": SSLyze().start_scan(session_id, ctx)}
    except TimeLimitExceeded:
        return ScannerTaskResult(
            scanner="sslyze",
            phase="asset",
            status="timeout",
            result=None,
            error="Celery time limit exceeded",
            runtime_ms=300
        ).model_dump()


# Phase 1.1: Technology Discovery

@celery_app.task(
    bind=True,
    soft_time_limit=240,
    time_limit=300,
)
def task_whatweb(self, liveliness_ctx: str, session_id: str, ctx_json: str) -> dict:
    try:
        ctx = ScanContext(**json.loads(ctx_json))
        return {"type": "whatweb", "result": WhatWeb().start_scan(session_id, ctx)}
    except TimeLimitExceeded:
        return ScannerTaskResult(
            scanner="whatweb",
            phase="asset",
            status="timeout",
            result=None,
            error="Celery time limit exceeded",
            runtime_ms=300
        ).model_dump()

@celery_app.task(
    bind=True,
    soft_time_limit=240,
    time_limit=300,
)
def task_wappalyzer(self, liveliness_ctx: str, session_id: str, ctx_json: str) -> dict:
    try:
        ctx = ScanContext(**json.loads(ctx_json))
        return {"type": "wappalyzer", "result": WappalyzerNext().start_scan(session_id, ctx)}
    except TimeLimitExceeded:
        return ScannerTaskResult(
            scanner="wappalyzer",
            phase="asset",
            status="timeout",
            result=None,
            error="Celery time limit exceeded",
            runtime_ms=300
        ).model_dump()

#noinspection D
@celery_app.task(
    bind=True,
    soft_time_limit=240,
    time_limit=300,
)
def task_build_asset_context(self, results: list[dict], session_id: str):
    # Create the preamble context
    # The only requirement for the next phase is subfinder discoveries. If None, HTTPX should just check the main domain
    raw = redis_client.get(f"discovery:{session_id}")
    if raw is None:
        raise ValueError(f"Missing discovery context for session {session_id}")
    discovery_ctx = DiscoveryContext.model_validate_json(raw)
    try:
        assert results is not None
        for result in results:
            item = ScannerTaskResult.model_validate(result.get("result"))
            assert item is not None
            if item.status != "success":
                logger.warning(f"{item.scanner} skipped. Errors: {item.error}")
                continue
            if discovery_ctx.cpes is None:
                discovery_ctx.cpes = []
            if discovery_ctx.technologies is None:
                discovery_ctx.technologies = []

            match item.scanner:
                case "sslyze":
                    if item.result is None:
                        logger.warning("SSLyze returned without results")
                        continue
                    discovery_ctx.ssl_certs = item.result
                case "whatweb":
                    if item.result is None:
                        logger.warning("WhatWeb returned without results")
                        continue
                    discovery_ctx.technologies.extend(resolve_tech_to_tech_entry(item.result["technologies"]))
                    discovery_ctx.cpes.extend(tech_to_cpe(resolve_tech_to_tech_entry(item.result["technologies"])))
                case "wappalyzer":
                    if item.result is None:
                        logger.warning("Wappalyzer-next returned without results")
                        continue
                    discovery_ctx.technologies.extend(resolve_tech_to_tech_entry(item.result["technologies"]))
                    discovery_ctx.cpes.extend(tech_to_cpe(resolve_tech_to_tech_entry(item.result["technologies"])))

        with transaction() as db:
            # insert database entry for discovery context here since this is where we consider it "complete"
            db.add(DiscoveryContextModel(
                scan_id=uuid.UUID(session_id, version=4),
                site_map=discovery_ctx.site_map,
                endpoints=discovery_ctx.endpoints,
                out_of_scope=discovery_ctx.out_of_scope,
                ports=discovery_ctx.ports,
                domains=discovery_ctx.domains,
                cpes=discovery_ctx.cpes,
                queried_vulnerabilities=discovery_ctx.queried_vulnerabilities,
                ssl_certs=discovery_ctx.ssl_certs
            ))
    except Exception as e:
        logger.exception(e)
        mark_phase_as_errored(
            report_id=session_id,
            phase=ScanPhase.ASSET,
        )
        raise
    mark_phase_as(
        report_id=session_id,
        phase=ScanPhase.ASSET,
    )
    redis_client.set(f"phase:{session_id}", "attack")
    redis_client.set(f"discovery:{session_id}", discovery_ctx.model_dump_json())