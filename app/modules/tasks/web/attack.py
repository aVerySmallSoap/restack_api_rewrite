import json
from pathlib import Path

from billiard.exceptions import TimeLimitExceeded
from loguru import logger

from app.modules.scanners.web.nuclei.nuclei import Nuclei
from app.services.celery_app import celery_app
from app.modules.interfaces.types.options import ScannerTaskResult
from app.modules.interfaces.types.context import ScanContext, redis_client
from app.modules.scanners.web.wapiti.wapiti_scanner import WapitiScanner
from app.modules.scanners.web.zap.zap_scanner import ZapScanner
from app.modules.tasks.discovery.discovery_context import DiscoveryContext
from app.modules.tasks.web.attack_context import AttackContext


@celery_app.task(
    bind=True,
    soft_time_limit=16000,
    time_limit=18000,
)
def task_nuclei(self, previous_context: str, session_id:str, scan_context: str):
    try:
        ctx = ScanContext(**json.loads(scan_context))
        return {"type": "nuclei", "result": Nuclei().start_scan(session_id, ctx)}
    except TimeLimitExceeded:
        return ScannerTaskResult(
            scanner="nuclei",
            phase="attack",
            status="timeout",
            result=None,
            error="Celery time limit exceeded",
            runtime_ms=300
        ).model_dump()

@celery_app.task(
    bind=True,
    soft_time_limit=16000,
    time_limit=18000,
)
def task_wapiti(self, previous_context: str, session_id:str, scan_context: str):
    try:
        ctx = ScanContext(**json.loads(scan_context))
        return {"type": "wapiti", "result": WapitiScanner().start_scan(session_id, ctx)}
    except TimeLimitExceeded:
        return ScannerTaskResult(
            scanner="wapiti",
            phase="attack",
            status="timeout",
            result=None,
            error="Celery time limit exceeded",
            runtime_ms=300
        ).model_dump()

@celery_app.task(
    bind=True,
    soft_time_limit=16000,
    time_limit=18000,
)
def task_zap(self, previous_context: str, session_id:str, scan_context: str):
    try:
        ctx = ScanContext(**json.loads(scan_context))
        return {"type": "zap", "result": ZapScanner().start_scan(session_id, ctx)}
    except TimeLimitExceeded:
        return ScannerTaskResult(
            scanner="zap",
            phase="attack",
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
def task_build_attack_context(self, results: list[dict], session_id: str):
    raw = redis_client.get(f"discovery:{session_id}")
    print(results)
    if raw is None:
        raise ValueError(f"Missing discovery context for session {session_id}")
    discovery_ctx = DiscoveryContext.model_validate_json(raw)
    attack_ctx = AttackContext(data=None, discovery_context=discovery_ctx)
    try:
        assert results is not None
        for result in results:
            item = ScannerTaskResult.model_validate(result.get("result"))
            assert item is not None
            if item.status != "success":
                logger.warning(f"{item.scanner} skipped. Errors: {item.error}")
                continue

            match item.scanner:
                case "nuclei":
                    print(item.result)
                case "wapiti":
                    print(item.result)
                case "zap":
                    print(item.result)
        with open(f"{Path.cwd()}/app/reports/test.json", "w") as f:
            f.write(json.dumps(attack_ctx.model_dump_json(), indent=4))
    except AssertionError as e:
        logger.error("An object has an unexpected value!")
        logger.exception(e)
        raise
    except Exception as e:
        logger.error("Something unexpected happened!")
        logger.exception(e)
        raise
    redis_client.set(f"attack:{session_id}", attack_ctx.model_dump_json())
