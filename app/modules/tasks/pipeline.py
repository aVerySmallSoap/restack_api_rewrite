from celery import chain, chord, group
from app.modules.tasks.discovery_tasks import (
    task_subfinder, task_naabu, task_katana,
    task_httpx, task_sslyze, task_wappalyzer, task_whatweb
)
from app.modules.pipeline.context import DiscoveryContext

def launch_pipeline(session_id: str, ctx: DiscoveryContext):
    ctx_json = ctx.to_json()

    # Asset Discovery
    # Phase 0: Preamble

    preamble_chord = group(
            task_katana.si(session_id, ctx_json),
            task_naabu.si(session_id, ctx_json),
            task_subfinder.si(session_id, ctx_json),
        )

    # Phase 0.5: Liveliness

    liveliness_chord = group(
            task_httpx.si(session_id, ctx_json),
        )

    # Phase 1 & 1.1: Context Building and Technology Discovery
    context_chord = group(
            task_sslyze.si(session_id, ctx_json),
            task_wappalyzer.si(session_id, ctx_json),
            task_whatweb.si(session_id, ctx_json),
        )

    full_pipeline = chain(
        preamble_chord,
        liveliness_chord,
        context_chord,
    )
    full_pipeline.delay()