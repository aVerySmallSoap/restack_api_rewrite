from celery import chain, chord, group
from app.modules.tasks.discovery_tasks import (
    task_subfinder, task_httpx, task_sslyze,
    task_whatweb, task_wappalyzer,
    build_discovery_context, build_enumeration_context
)
from app.modules.pipeline.context import DiscoveryContext
from app.modules.tasks.discovery_tasks import task_katana


# from app.modules.tasks.scanning_tasks import ... (Phase 2, future)

def launch_pipeline(session_id: str, ctx: DiscoveryContext):
    ctx_json = ctx.to_json()

    # phase 0: enumeration
    enumeration_chord = chord(
        group(
            task_katana.s(session_id, ctx_json),
            task_subfinder.s(session_id, ctx_json),
        ),
        build_enumeration_context.s(session_id, ctx_json),
    )

    discovery_chord = chord(
        group(
            task_httpx.si(session_id, ctx_json),
            task_sslyze.si(session_id, ctx_json),
            task_whatweb.si(session_id, ctx_json),
            task_wappalyzer.si(session_id, ctx_json),
        ),
        build_discovery_context.s(session_id)  # fires when all 4 finish
    )

    full_pipeline = chain(
        enumeration_chord,
        discovery_chord
    )

    # When Phase 2 exists, you'd do:
    # full_pipeline = chain(discovery_chord, phase2_chord, ...)
    # full_pipeline.delay()

    full_pipeline.delay()