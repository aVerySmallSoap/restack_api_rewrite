import json

import orjson
from loguru import logger

from app.modules.celery_app import celery_app
from app.modules.pipeline.context import ScanContext
from app.modules.scanners.discovery import Katana, Naabu, Subfinder
from app.modules.tasks.discovery.contexts.discovery_context import DiscoveryContext
from app.modules.tasks.discovery.contexts.preamble_context import PreambleContext


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
def task_build_preamble_context(self, results: list[dict], discovery_context: str):
    discovery_ctx = DiscoveryContext(**json.loads(discovery_context))
    site_map: dict = {}
    endpoints: list[str] = []
    out_of_scope: list[str] = []
    ports: list[int] = []
    domains: list[str] = []
    try:
        assert results is not None
        for result in results:
            match result["type"]:
                case "katana":
                    site_map = result["result"]["siteMap"]
                    endpoints = result["result"]["endPoints"]
                    out_of_scope = result["result"]["outOfScope"]
                case "naabu":
                    ports = result["result"]["ports"]
                case "subfinder":
                    domains = result["result"]
    except AssertionError as e:
        logger.error("An object has an unexpected value!")
        logger.exception(e)
        raise
    except Exception as e:
        logger.error("Something unexpected happened!")
        logger.exception(e)
        raise
    # always serialize before sending
    preamble_context = PreambleContext(
        site_map=site_map,
        endpoints=endpoints,
        out_of_scope=out_of_scope,
        ports=ports,
        domains=domains
    )
    discovery_ctx.preamble_context = preamble_context
    return preamble_context.model_dump()