from celery import chain, chord, group

from app.modules.tasks import (
    task_katana, task_naabu, task_subfinder, task_build_preamble_context,
    task_httpx, task_build_liveliness_context,
    task_sslyze, task_whatweb, task_wappalyzer, task_build_asset_context
)
from modules.interfaces.types.context import ScanContext, redis_client
from app.modules.tasks.discovery.discovery_context import DiscoveryContext
from app.modules.tasks.discovery.minor_tasks import task_search_vuln_query
from app.modules.tasks.web.attack import (
    task_nuclei, task_wapiti, task_zap, task_build_attack_context
)


def launch_pipeline(session_id: str, ctx: ScanContext):
    from loguru import logger
    logger.info(f"Starting a new scan with session: {session_id}")
    discovery_context = DiscoveryContext()
    redis_client.set(f"discovery:{session_id}", discovery_context.model_dump_json())
    ctx_json = ctx.to_json()
    discovery_json = discovery_context.model_dump_json()

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
    )
    full_pipeline.apply_async()