import json

from loguru import logger

from app.modules.celery_app import celery_app
from app.modules.pipeline.context import ScanContext
from app.modules.scanners.discovery import (
    SSLyze, WhatWeb, WappalyzerNext
)
from app.modules.tasks.discovery.contexts.discovery_context import DiscoveryContext
from app.modules.tasks.discovery.contexts.asset_context import AssetContext


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
def task_build_asset_context(self, results: list[dict], discovery_context: str):
    # Create the preamble context
    # The only requirement for the next phase is subfinder discoveries. If None, HTTPX should just check the main domain
    discovery_ctx = DiscoveryContext(**json.loads(discovery_context))
    asset = AssetContext()
    try:
        assert results is not None
        for result in results:
            match result["type"]:
                case "sslyze":
                    pass
                case "whatweb":
                    pass
                case "wappalyzer":
                    pass
    except AssertionError as e:
        logger.error("An object has an unexpected value!")
        logger.exception(e)
        raise
    except Exception as e:
        logger.error("Something unexpected happened!")
        logger.exception(e)
        raise
    # always serialize before sending
    discovery_ctx.asset_context = asset
    print(results)
    return asset.model_dump()