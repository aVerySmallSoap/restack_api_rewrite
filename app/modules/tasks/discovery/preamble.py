import json

from loguru import logger

from app.modules.celery_app import celery_app
from app.modules.pipeline.context import ScanContext, redis_client
from app.modules.scanners.discovery import Katana, Naabu, Subfinder
from app.modules.tasks.discovery.discovery_context import DiscoveryContext


@celery_app.task(bind=True)
def task_katana(self, session_id:str, ctx_json: str) -> dict:
    ctx = ScanContext(**json.loads(ctx_json))
    return {"type": "katana", "result": Katana().start_scan(session_id, ctx)}

# Discover any open ports
@celery_app.task(bind=True)
def task_naabu(self, session_id:str, ctx_json: str) -> dict:
    ctx = ScanContext(**json.loads(ctx_json))
    return {"type": "naabu", "result": Naabu().start_scan(session_id, ctx)}

# Find any related domains
@celery_app.task(bind=True)
def task_subfinder(self, session_id: str, ctx_json: str) -> dict:
    ctx = ScanContext(**json.loads(ctx_json))
    return {"type": "subfinder", "result": Subfinder().start_scan(session_id, ctx)}

@celery_app.task(bind=True)
def task_build_preamble_context(self, results: list[dict], discovery_context: str, session_id: str):
    discovery_ctx = DiscoveryContext(**json.loads(discovery_context))
    try:
        assert results is not None
        for result in results:
            match result["type"]:
                case "katana":
                    discovery_ctx.site_map = result["result"]["siteMap"]
                    discovery_ctx.endpoints = result["result"]["endPoints"]
                    discovery_ctx.out_of_scope = result["result"]["outOfScope"]
                case "naabu":
                    discovery_ctx.ports = result["result"]["ports"]
                case "subfinder":
                    discovery_ctx.domains = result["result"]
    except AssertionError as e:
        logger.error("An object has an unexpected value!")
        logger.exception(e)
        raise
    except Exception as e:
        logger.error("Something unexpected happened!")
        logger.exception(e)
        raise
    redis_client.set(f"discovery:{session_id}", discovery_ctx.model_dump_json())