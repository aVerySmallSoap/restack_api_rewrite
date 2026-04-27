import json

from billiard.exceptions import TimeLimitExceeded
from loguru import logger

from app.services.celery_app import celery_app
from modules.interfaces.types.context import ScanContext, redis_client
from app.modules.scanners.discovery import Katana, Naabu, Subfinder
from app.modules.tasks.discovery.discovery_context import DiscoveryContext
from app.modules.interfaces.types.options import ScannerTaskResult

@celery_app.task(
    bind=True,
    soft_time_limit=300,
    time_limit=600,
)
def task_katana(self, session_id:str, ctx_json: str) -> dict:
    try:
        ctx = ScanContext(**json.loads(ctx_json))
        return {"type": "katana", "result": Katana().start_scan(session_id, ctx)}
    except TimeLimitExceeded:
        return ScannerTaskResult(
            scanner="katana",
            phase="preamble",
            status="timeout",
            result=None,
            error="Celery time limit exceeded",
            runtime_ms=300
        ).model_dump()

# Discover any open ports
@celery_app.task(
    bind=True,
    soft_time_limit=240,
    time_limit=300,
)
def task_naabu(self, session_id:str, ctx_json: str) -> dict:
    try:
        ctx = ScanContext(**json.loads(ctx_json))
        return {"type": "naabu", "result": Naabu().start_scan(session_id, ctx)}
    except TimeLimitExceeded:
        return ScannerTaskResult(
            scanner="naabu",
            phase="preamble",
            status="timeout",
            result=None,
            error="Celery time limit exceeded",
            runtime_ms=300
        ).model_dump()

# Find any related domains
@celery_app.task(
    bind=True,
    soft_time_limit=240,
    time_limit=300,
)
def task_subfinder(self, session_id: str, ctx_json: str) -> dict:
    try:
        ctx = ScanContext(**json.loads(ctx_json))
        return {"type": "subfinder", "result": Subfinder().start_scan(session_id, ctx)}
    except TimeLimitExceeded:
        return ScannerTaskResult(
            scanner="subfinder",
            phase="preamble",
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
def task_build_preamble_context(self, results: list[dict], discovery_context: str, session_id: str):
    discovery_ctx = DiscoveryContext(**json.loads(discovery_context))
    try:
        assert results is not None
        for result in results:
            item = ScannerTaskResult.model_validate(result.get("result"))
            assert item is not None
            if item.status != "success":
                logger.warning(f"{item.scanner} skipped. Errors: {item.error}")
                continue

            match item.scanner:
                case "katana":
                    if item.result is None:
                        logger.warning(f"Katana returned without results")
                        continue
                    discovery_ctx.site_map = item.result["siteMap"]
                    discovery_ctx.endpoints = item.result["endPoints"]
                    discovery_ctx.out_of_scope = item.result["outOfScope"]
                case "naabu":
                    if item.result is None:
                        logger.warning(f"Naabu returned without results")
                        continue
                    discovery_ctx.ports = item.result["ports"]
                case "subfinder":
                    if item.result is None:
                        logger.warning(f"Subfinder returned without results")
                        continue
                    discovery_ctx.domains = item.result
    except AssertionError as e:
        logger.error("An object has an unexpected value!")
        logger.exception(e)
        raise AssertionError
    except Exception as e:
        logger.error("Something unexpected happened!")
        logger.exception(e)
        raise RuntimeWarning
    redis_client.set(f"discovery:{session_id}", discovery_ctx.model_dump_json())