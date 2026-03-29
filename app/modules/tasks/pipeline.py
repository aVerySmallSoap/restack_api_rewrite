from celery import chain, chord, group
from app.modules.tasks.discovery_tasks import (
    task_subfinder, build_enumeration_context
)
from app.modules.pipeline.context import DiscoveryContext
from app.modules.tasks.discovery_tasks import task_katana
from app.modules.tasks.discovery_tasks import launch_discovery_phase


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

    full_pipeline = chain(
        enumeration_chord,
        launch_discovery_phase.s(session_id)
    )

    # When Phase 2 exists, you'd do:
    # full_pipeline = chain(discovery_chord, phase2_chord, ...)
    # full_pipeline.delay()

    full_pipeline.delay()