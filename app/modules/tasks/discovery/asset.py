import json
from pathlib import Path

from loguru import logger

from app.modules.celery_app import celery_app
from app.modules.pipeline.context import ScanContext, redis_client, TechEntry
from app.modules.scanners.discovery import (
    SSLyze, WhatWeb, WappalyzerNext
)
from app.modules.tasks.discovery.discovery_context import DiscoveryContext
from app.modules.utils.utils import tech_to_cpe, resolve_tech_to_tech_entry


@celery_app.task(bind=True)
def task_sslyze(self, liveliness_ctx: str, session_id: str, ctx_json: str) -> dict:
    ctx = ScanContext(**json.loads(ctx_json))
    return {"type": "sslyze", "result": SSLyze().start_scan(session_id, ctx)}

# Phase 1.1: Technology Discovery

@celery_app.task(bind=True)
def task_whatweb(self, liveliness_ctx: str, session_id: str, ctx_json: str) -> dict:
    ctx = ScanContext(**json.loads(ctx_json))
    return {"type": "whatweb", "result": WhatWeb().start_scan(session_id, ctx)}

@celery_app.task(bind=True)
def task_wappalyzer(self, liveliness_ctx: str, session_id: str, ctx_json: str) -> dict:
    ctx = ScanContext(**json.loads(ctx_json))
    return {"type": "wappalyzer", "result": WappalyzerNext().start_scan(session_id, ctx)}

@celery_app.task(bind=True)
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
            match result["type"]:
                case "sslyze":
                    pass
                case "whatweb":
                    assert discovery_ctx.cpes is not None
                    assert discovery_ctx.technologies is not None
                    assert result["result"] is not None
                    discovery_ctx.technologies.extend(resolve_tech_to_tech_entry(result["result"]["technologies"]))
                    discovery_ctx.cpes.extend(tech_to_cpe(resolve_tech_to_tech_entry(result["result"]["technologies"])))
                case "wappalyzer":
                    assert discovery_ctx.cpes is not None
                    assert discovery_ctx.technologies is not None
                    assert result["result"] is not None
                    discovery_ctx.technologies.extend(resolve_tech_to_tech_entry(result["result"]["technologies"]))
                    discovery_ctx.cpes.extend(tech_to_cpe(resolve_tech_to_tech_entry(result["result"]["technologies"])))
    except AssertionError as e:
        logger.error("An object has an unexpected value!")
        logger.exception(e)
        raise
    except Exception as e:
        logger.error("Something unexpected happened!")
        logger.exception(e)
        raise
    redis_client.set(f"discovery:{session_id}", discovery_ctx.model_dump_json())