import json

from loguru import logger
from orjson import orjson

from app.modules.celery_app import celery_app
from app.modules.scanners.discovery import HttpxScanner
from app.modules.tasks.discovery.contexts.preamble_context import PreambleContext
from app.modules.pipeline.context import ScanContext
from app.modules.tasks.discovery.contexts.liveliness_context import LivelinessContext
from app.modules.tasks.discovery.contexts.discovery_context import DiscoveryContext


@celery_app.task(bind=True)
def task_httpx(self, preamble_ctx: dict, session_id: str, ctx: str) -> dict:
    scan_context = ScanContext(**json.loads(ctx))
    preamble_context = PreambleContext(**preamble_ctx)
    return {"type": "httpx", "result": HttpxScanner().start_scan(session_id, scan_context, preamble_context)}

@celery_app.task(bind=True)
def task_build_liveliness_context(self, results: list[dict], discovery_context: str):
    # Create the preamble context
    # The only requirement for the next phase is subfinder discoveries. If None, HTTPX should just check the main domain
    discovery_ctx = DiscoveryContext(**json.loads(discovery_context))
    liveliness = LivelinessContext()
    try:
        assert results is not None
        for result in results:
            match result["type"]:
                case "httpx":
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
    discovery_ctx.liveliness_context = liveliness
    print(discovery_ctx)
    return liveliness.model_dump()