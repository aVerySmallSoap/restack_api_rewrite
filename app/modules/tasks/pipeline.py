from celery import chain, chord, group
from orjson import orjson

from app.modules.tasks import (
    task_katana, task_naabu, task_subfinder, task_build_preamble_context,
    task_httpx, task_build_liveliness_context
)
from app.modules.pipeline.context import ScanContext
from app.modules.tasks.discovery.contexts.discovery_context import DiscoveryContext


def launch_pipeline(session_id: str, ctx: ScanContext):
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

    full_pipeline = chain(
        preamble_phase, # Phase 0: Is anything there?
        liveliness_phase # Phase 0.5: Is anything alive? Is there something inside?
    )
    full_pipeline.apply_async()