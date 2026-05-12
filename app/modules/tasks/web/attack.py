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
from app.modules.database.persistance.phases import mark_phase_as_errored, mark_phase_as
from app.modules.interfaces.enums.scan_tracking import ScanPhase
from app.modules.database.persistance.alerts import insert_nuclei_alerts
from app.modules.database.persistance.alerts import insert_wapiti_alerts, insert_zap_alerts


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
                    if item.result is None:
                        logger.warning("Skipping Nuclei results! Reason: empty result")
                        continue
                    attack_ctx.nuclei_result = item.result
                    insert_nuclei_alerts(item.result, session_id)
                case "wapiti":
                    if item.result is None:
                        logger.warning("Skipping Wapiti results! Reason: empty result")
                        continue
                    attack_ctx.wapiti_result = item.result
                    insert_wapiti_alerts(item.result, session_id)
                case "zap":
                    if item.result is None:
                        logger.warning("Skipping Wapiti results! Reason: empty result")
                        continue
                    attack_ctx.zap_result = item.result
                    insert_zap_alerts(item.result, session_id)
        with open(f"{Path.cwd()}/app/reports/attack_context_{session_id}.json", "w") as f:
            f.write(attack_ctx.model_dump_json(indent=4))
    except Exception as e:
        logger.exception(e)
        mark_phase_as_errored(
            report_id=session_id,
            phase=ScanPhase.ATTACK,
        )
        raise
    mark_phase_as(
        report_id=session_id,
        phase=ScanPhase.ATTACK,
    )
    redis_client.set(f"attack:{session_id}", attack_ctx.model_dump_json())
