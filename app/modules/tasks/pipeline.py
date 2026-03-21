from celery import chain, chord, group
from app.modules.tasks.discovery_tasks import (
    task_subfinder, task_httpx, task_sslyze,
    task_whatweb, task_wappalyzer,
    build_discovery_context,
)
from app.modules.pipeline.context import DiscoveryContext

# from app.modules.tasks.scanning_tasks import ... (Phase 2, future)

def launch_pipeline(session_id: str, ctx: DiscoveryContext):
    ctx_json = ctx.to_json()

    discovery_chord = chord(
        group(
            task_subfinder.s(session_id, ctx_json),
            task_httpx.s(session_id, ctx_json),
            task_sslyze.s(session_id, ctx_json),
            task_whatweb.s(session_id, ctx_json),
            task_wappalyzer.s(session_id, ctx_json),
        ),
        build_discovery_context.s(session_id, ctx_json)  # fires when all 5 finish
    )

    # When Phase 2 exists, you'd do:
    # full_pipeline = chain(discovery_chord, phase2_chord, ...)
    # full_pipeline.delay()

    discovery_chord.delay()