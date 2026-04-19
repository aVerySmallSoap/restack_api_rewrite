from celery import chain, chord, group

from app.modules.tasks import (
    task_katana, task_naabu, task_subfinder, task_build_preamble_context,
    task_httpx, task_build_liveliness_context,
    task_sslyze, task_whatweb, task_wappalyzer, task_build_asset_context
)
from app.modules.pipeline.context import ScanContext
from app.modules.tasks.discovery.contexts.discovery_context import DiscoveryContext


def launch_pipeline(session_id: str, ctx: ScanContext):
    from loguru import logger
    logger.info(f"Starting a new scan with session: {session_id}")
    #init
    discovery_context = DiscoveryContext()
    #serialize
    ctx_json = ctx.to_json()
    discovery_json = discovery_context.to_json()

    # Asset Discovery

    preamble_phase = chord(
        group(
            task_katana.s(session_id, ctx_json),
            task_naabu.s(session_id, ctx_json),
            task_subfinder.s(session_id, ctx_json),
        ),
        task_build_preamble_context.s(discovery_json)
    )

    liveliness_phase = chord(
        group(
            task_httpx.s(session_id, ctx_json),
        ),
        task_build_liveliness_context.s(discovery_json),
    )

    asset_phase = chord(
        group(
            task_sslyze.s(session_id, ctx_json),
            task_whatweb.s(session_id, ctx_json),
            task_wappalyzer.s(session_id, ctx_json),
        ),
        task_build_asset_context.s(discovery_json),
    )

    # Stop-gap: Query vulnerable tek!

    full_pipeline = chain(
        preamble_phase, # Phase 0: Is anything there?
        liveliness_phase, # Phase 0.5: Is anything alive? Is there something inside?
        asset_phase, # Phase 0.7: Is there any significant information?
    )
    full_pipeline.apply_async()