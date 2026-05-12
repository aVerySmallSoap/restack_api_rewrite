import json
import uuid
from uuid import uuid4

from billiard import TimeLimitExceeded
from loguru import logger

from app.services.celery_app import celery_app
from app.modules.scanners.discovery import HttpxScanner
from app.modules.interfaces.types.context import ScanContext, redis_client
from app.modules.tasks.discovery.discovery_context import DiscoveryContext
from app.modules.utils.utils import tech_to_cpe, resolve_tech_to_tech_entry
from app.modules.interfaces.types.options import ScannerTaskResult
from app.modules.database.persistance.phases import mark_phase_as_errored, mark_phase_as
from app.modules.interfaces.enums.scan_tracking import ScanPhase
from app.modules.database.database import transaction
from app.modules.interfaces.types.context import TechnologyEntry
from app.modules.database.models.findings import TechnologiesModel


@celery_app.task(
    bind=True,
    soft_time_limit=240,
    time_limit=300,
)
def task_httpx(self, preamble_context: str, session_id: str, ctx: str) -> dict:
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
            assert isinstance(item, ScannerTaskResult)
            if item.status != "success":
                logger.warning(f"{item.scanner} skipped. Errors: {item.error}")
                continue
            discovery_ctx.cpes = []
            discovery_ctx.technologies = []

            match item.scanner:
                case "httpx": # this assumes to be the first to fill the Discovery Context's technologies cpe field
                    if item.result is None:
                        logger.warning("HTTPX returned without results")
                        raise RuntimeWarning
                    assert item.result is not None
                    assert isinstance(item.result, dict)
                    technologies = item.result.get("technologies", None)
                    cpes = item.result.get("cpe", None)
                    if technologies:
                        with transaction() as db:
                            _appendable = []
                            for tech in item.result["technologies"]:
                                tech = TechnologyEntry.model_validate(tech)
                                _appendable.append(
                                    TechnologiesModel(
                                        scan_id=uuid.UUID(session_id, version=4),
                                        name=tech.name,
                                        source="httpx",
                                        version=[tech.version] if isinstance(tech.version, str) else tech.version if tech.version else None,
                                        blob=tech.model_dump()
                                    )
                                )
                            db.add_all(_appendable)
                        discovery_ctx.technologies = item.result["technologies"]
                    if cpes:
                        cpe_list: list = item.result["cpe"]
                        cpe_list.extend(tech_to_cpe(resolve_tech_to_tech_entry(item.result["technologies"])))
                        discovery_ctx.cpes = cpe_list
    except Exception as e:
        logger.exception(e)
        mark_phase_as_errored(
            report_id=session_id,
            phase=ScanPhase.LIVELINESS,
        )
        raise
    mark_phase_as(
        report_id=session_id,
        phase=ScanPhase.LIVELINESS,
    )
    redis_client.set(f"phase:{session_id}", "liveliness")
    redis_client.set(f"discovery:{session_id}", discovery_ctx.model_dump_json())