import json

from loguru import logger

from app.modules.celery_app import celery_app
from app.modules.scanners.discovery import HttpxScanner
from app.modules.pipeline.context import ScanContext, redis_client
from app.modules.tasks.discovery.discovery_context import DiscoveryContext
from app.modules.utils.utils import tech_to_cpe, resolve_tech_to_tech_entry


@celery_app.task(bind=True)
def task_httpx(self, preamble_ctx: dict, session_id: str, ctx: str) -> dict:
    scan_context = ScanContext(**json.loads(ctx))
    return {"type": "httpx", "result": HttpxScanner().start_scan(session_id, scan_context)}

@celery_app.task(bind=True)
def task_build_liveliness_context(self, results: list[dict], session_id: str):
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
                case "httpx": # this assumes to be the first to fill the Discovery Context's technologies cpe field
                    if discovery_ctx.cpes is None:
                        discovery_ctx.cpes = []
                    if discovery_ctx.technologies is None:
                        if result["result"]["technologies"] is not None:
                            discovery_ctx.technologies = result["result"]["technologies"]
                        else:
                            discovery_ctx.technologies = []
                    cpe_list: list = result["result"]["cpe"]
                    cpe_list.extend(tech_to_cpe(resolve_tech_to_tech_entry(result["result"]["technologies"])))
                    discovery_ctx.cpes = cpe_list
    except AssertionError as e:
        logger.error("An object has an unexpected value!")
        logger.exception(e)
        raise
    except Exception as e:
        logger.error("Something unexpected happened!")
        logger.exception(e)
        raise
    redis_client.set(f"discovery:{session_id}", discovery_ctx.model_dump_json())