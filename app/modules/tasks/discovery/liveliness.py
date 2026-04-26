import json

from billiard import TimeLimitExceeded
from loguru import logger

from app.services.celery_app import celery_app
from app.modules.scanners.discovery import HttpxScanner
from app.modules.pipeline.context import ScanContext, redis_client
from app.modules.tasks.discovery.discovery_context import DiscoveryContext
from app.modules.utils.utils import tech_to_cpe, resolve_tech_to_tech_entry
from app.modules.interfaces.types.options import ScannerTaskResult


@celery_app.task(
    bind=True,
    soft_time_limit=240,
    time_limit=300,
)
def task_httpx(self, preamble_ctx: dict, session_id: str, ctx: str) -> dict:
    try:
        scan_context = ScanContext(**json.loads(ctx))
        return {"type": "httpx", "result": HttpxScanner().start_scan(session_id, scan_context)}
    except TimeLimitExceeded:
        return ScannerTaskResult(
            scanner="httpx",
            phase="preamble",
            status="timeout",
            result=None,
            error="Celery time limit exceeded",
            runtime_ms=300
        ).model_dump()


# noinspection D
@celery_app.task(
    bind=True,
    soft_time_limit=240,
    time_limit=300,
    )
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
            item = ScannerTaskResult.model_validate(result.get("result"))
            assert item is not None
            if item.status != "success":
                logger.warning(f"{item.scanner} skipped. Errors: {item.error}")
                continue

            match item.scanner:
                case "httpx": # this assumes to be the first to fill the Discovery Context's technologies cpe field
                    if discovery_ctx.cpes is None:
                        discovery_ctx.cpes = []
                    if discovery_ctx.technologies is None:
                        if item.result["technologies"] is not None:
                            discovery_ctx.technologies = item.result["technologies"]
                        else:
                            discovery_ctx.technologies = []
                    cpe_list: list = item.result["cpe"]
                    cpe_list.extend(tech_to_cpe(resolve_tech_to_tech_entry(item.result["technologies"])))
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