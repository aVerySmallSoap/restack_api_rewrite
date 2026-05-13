from datetime import datetime
from loguru import logger

from celery import chain, chord, group

from app.modules.tasks import (
    task_katana, task_naabu, task_subfinder, task_build_preamble_context,
    task_httpx, task_live_check, task_build_liveliness_context,
    task_sslyze, task_whatweb, task_wappalyzer, task_build_asset_context
)
from app.modules.interfaces.types.context import ScanContext, redis_client
from app.modules.tasks.discovery.discovery_context import DiscoveryContext
from app.modules.tasks.discovery.query import task_search_vuln_query
from app.modules.tasks.web.attack import (
    task_nuclei, task_wapiti, task_zap, task_build_attack_context
)
from app.modules.tasks.normalization.normalization import task_basic_normalization
from app.modules.database.persistance.scans import create_scan
from app.modules.interfaces.enums.scan_tracking import ScanTypes
from app.modules.interfaces.types.options import ScannerTaskResult
from app.modules.tasks.analytics.report_analytics import task_generate_report_analytics
from app.modules.database.persistance.phases import mark_phase_as
from app.modules.interfaces.enums.scan_tracking import ScanPhase
from app.modules.tasks.discovery.query import task_quick_scan_end


def is_target_responsive(session_id: str, ctx: ScanContext) -> bool:
    task = task_live_check.apply_async((session_id, ctx.model_dump_json()))
    result = task.get()
    if result:
        logger.debug("We received a response from httpx")
        scanner_result = ScannerTaskResult.model_validate(result["result"])
        if scanner_result.result is None:
            logger.warning("HTTPX returned nothing while checking! Is this a bug?")
            logger.warning(scanner_result.result)
            return False
        httpx_result_failed = scanner_result.result.get("failed", None)
        if httpx_result_failed is None:
            logger.warning("HTTPX returned nothing while checking! Is this a bug?")
            logger.exception(httpx_result_failed)
            return False
        if httpx_result_failed:
            logger.error("Target host is not reachable!")
            return False
        else:
            logger.success("Target host is reachable!")
            return True
    logger.error("Target host is not reachable!")
    return False

def launch_full_pipeline(session_id: str, ctx: ScanContext):
    from loguru import logger
    logger.info(f"Starting a new scan with session: {session_id}")
    discovery_context = DiscoveryContext()
    redis_client.set(f"discovery:{session_id}", discovery_context.model_dump_json())
    ctx_json = ctx.model_dump_json()
    discovery_json = discovery_context.model_dump_json()

    # Need to inject httpx results since we run an HTTPX scan first

    # Create a scan record on the database
    create_scan(
        session_id=session_id,
        scan_type=ScanTypes.FULL,
        is_automated=False,
        scan_date=datetime.now(),
        target=ctx.primary_host
    )
    mark_phase_as(
        report_id=session_id,
        phase=ScanPhase.STARTING
    )

    # Asset Discovery

    preamble_phase = chord(
        group(
            task_katana.s(session_id, ctx_json),
            task_naabu.s(session_id, ctx_json),
            task_subfinder.s(session_id, ctx_json),
        ),
        task_build_preamble_context.s(discovery_json, session_id)
    )

    liveliness_phase = chord(
        group(
            task_httpx.s(session_id, ctx_json),
        ),
        task_build_liveliness_context.s(session_id),
    )

    asset_phase = chord(
        group(
            task_sslyze.s(session_id, ctx_json),
            task_whatweb.s(session_id, ctx_json),
            task_wappalyzer.s(session_id, ctx_json),
        ),
        task_build_asset_context.s(session_id),
    )

    # Stop-gap: Query vulnerable tek!

    attack_phase = chord(
        group(
            task_nuclei.s(session_id, ctx_json),
            task_wapiti.s(session_id, ctx_json),
            task_zap.s(session_id, ctx_json),
        ),
        task_build_attack_context.s(session_id),
    )

    full_pipeline = chain(
        preamble_phase, # Phase 0: Is anything there?
        liveliness_phase, # Phase 0.5: Is anything alive? Is there something inside?
        asset_phase, # Phase 0.7: Is there any significant information?
        task_search_vuln_query.s(session_id, ctx_json),
        attack_phase,
        task_basic_normalization.s(session_id),
        task_generate_report_analytics.s(session_id),
    )
    full_pipeline.apply_async()

def launch_quick_pipeline(session_id: str, ctx: ScanContext):
    from loguru import logger
    logger.info(f"Starting a new quick scan with session: {session_id}")
    discovery_context = DiscoveryContext()
    redis_client.set(f"discovery:{session_id}", discovery_context.model_dump_json())
    ctx_json = ctx.model_dump_json()
    discovery_json = discovery_context.model_dump_json()

    # Need to inject httpx results since we run an HTTPX scan first

    # Create a scan record on the database
    create_scan(
        session_id=session_id,
        scan_type=ScanTypes.QUICK,
        is_automated=False,
        scan_date=datetime.now(),
        target=ctx.primary_host
    )
    mark_phase_as(
        report_id=session_id,
        phase=ScanPhase.STARTING
    )

    # Asset Discovery

    preamble_phase = chord(
        group(
            task_katana.s(session_id, ctx_json),
            task_naabu.s(session_id, ctx_json),
            task_subfinder.s(session_id, ctx_json),
        ),
        task_build_preamble_context.s(discovery_json, session_id)
    )

    liveliness_phase = chord(
        group(
            task_httpx.s(session_id, ctx_json),
        ),
        task_build_liveliness_context.s(session_id),
    )

    asset_phase = chord(
        group(
            task_sslyze.s(session_id, ctx_json),
            task_whatweb.s(session_id, ctx_json),
            task_wappalyzer.s(session_id, ctx_json),
        ),
        task_build_asset_context.s(session_id),
    )

    quick_pipeline = chain(
        preamble_phase,  # Phase 0: Is anything there?
        liveliness_phase,  # Phase 0.5: Is anything alive? Is there something inside?
        asset_phase,  # Phase 0.7: Is there any significant information?
        task_search_vuln_query.s(session_id, ctx_json),
        task_quick_scan_end.s(session_id, ctx_json)
    )
    quick_pipeline.apply_async()
