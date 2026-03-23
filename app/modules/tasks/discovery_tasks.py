import json

from app.modules.pipeline.context import DiscoveryContext, TechEntry, BannerEntry, TLSFinding, SiteMap, \
    EnumerationContext
from app.modules.scanners.discovery.subfinder.subfinder import Subfinder
from app.modules.scanners.discovery.httpx_scanner.httpxscanner import HttpxScanner
from app.modules.scanners.discovery.sslyze.sslyze import SSLyze
from app.modules.scanners.discovery.whatweb.whatweb import WhatWeb
from app.modules.scanners.discovery.wappalyzer_next.wappalyzer_next import WappalyzerNext
from app.modules.scanners.discovery.katana.katana import Katana
from app.modules.celery_app import celery_app


@celery_app.task(bind=True)
def task_subfinder(self, session_id: str, ctx_json: str) -> dict:
    ctx = DiscoveryContext(**json.loads(ctx_json))
    return {"type": "subfinder", "result": Subfinder().start_scan(session_id, ctx)}

@celery_app.task(bind=True)
def task_katana(self, session_id:str, ctx_json: str) -> dict:
    ctx = DiscoveryContext(**json.loads(ctx_json))
    # TODO: is false for now. The is_two_pass argument will come from the request.
    return {"type": "katana", "result": Katana().start_scan(session_id, ctx, False)}

@celery_app.task(bind=True)
def task_httpx(self, session_id: str, ctx_json: str) -> dict:
    ctx = DiscoveryContext(**json.loads(ctx_json))
    return {"type": "httpx", "result": HttpxScanner().start_scan(session_id, ctx)}

@celery_app.task(bind=True)
def task_sslyze(self, session_id: str, ctx_json: str) -> dict:
    ctx = DiscoveryContext(**json.loads(ctx_json))
    return {"type": "sslyze", "result": SSLyze().start_scan(session_id, ctx)}

@celery_app.task(bind=True)
def task_whatweb(self, session_id: str, ctx_json: str) -> dict:
    ctx = DiscoveryContext(**json.loads(ctx_json))
    return {"type": "whatweb", "result": WhatWeb().start_scan(session_id, ctx)}

@celery_app.task(bind=True)
def task_wappalyzer(self, session_id: str, ctx_json: str) -> dict:
    ctx = DiscoveryContext(**json.loads(ctx_json))
    return {"type": "wappalyzer", "result": WappalyzerNext().start_scan(session_id, ctx)}


@celery_app.task(bind=True)
def build_discovery_context(self, results: list[dict], updated_ctx: str) -> str:
    """
    Chord callback — fires after all Phase 1 tasks finish.
    Merges all scanner results into DiscoveryContext and saves to Redis.
    Returns ctx_json for the next phase in the chain.
    """
    ctx = DiscoveryContext(**json.loads(updated_ctx))
    print(f"Enumeration Context type of site_map: {type(ctx.enumeration_context.site_map.map)}.")

    for item in results:
        result: dict = item["result"]
        if item["result"] is None or item["result"].values() == {}:
            continue
        match item["type"]:
            case "httpx":
                print(result)
                for host, banner_data in result.get("banners", {}).items():
                    ctx.banners[host] = BannerEntry(**banner_data)
                ctx.has_https = result.get("has_https", False)

            case "sslyze":
                for finding in result.get("tls_findings", []):
                    ctx.tls_findings.append(TLSFinding(**finding))

            case "whatweb" | "wappalyzer":
                for tech in result.get("versioned", []):
                    ctx.versioned_tech.append(TechEntry(**tech))
                for tech in result.get("nonversioned", []):
                    ctx.nonversioned_tech.append(TechEntry(**tech))

    # Derive nuclei tags from detected tech before saving
    # ctx.nuclei_tags = _derive_nuclei_tags(ctx)
    # ctx.save_to_redis()

    return ctx.to_json()  # passed into Phase 2 chain

@celery_app.task(bind=True)
def launch_discovery_phase(self, updated_ctx_json: str, session_id: str):
    """
    Bridge task — receives updated ctx_json from enumeration phase,
    then launches the discovery chord with it.
    """
    from celery import chord, group
    discovery_chord = chord(
        group(
            task_httpx.s(session_id, updated_ctx_json),
            task_sslyze.s(session_id, updated_ctx_json),
            task_whatweb.s(session_id, updated_ctx_json),
            task_wappalyzer.s(session_id, updated_ctx_json),
        ),
        build_discovery_context.s(updated_ctx_json),
    )
    return discovery_chord.delay()

@celery_app.task(bind=True)
def build_enumeration_context(self, results: list[dict], session_id: str, ctx_json: str) -> str:
    discovery_context = DiscoveryContext(**json.loads(ctx_json))
    enumeration_context = EnumerationContext()

    for item in results:
        result: dict = item["result"]
        if result is None or result.values() == {}:
            continue
        match item["type"]:
            case "subfinder":
                enumeration_context.hosts = result[discovery_context.primary_host].get("hosts", [])
            case "katana":
                enumeration_context.site_map = SiteMap(
                    collection=result.get("collection", []),
                    map=result.get("site_map", {})
                )
    discovery_context.enumeration_context = enumeration_context
    return discovery_context.to_json()

def _derive_nuclei_tags(ctx: DiscoveryContext) -> list[str]:
    """Build nuclei tag list from discovered tech — drives Phase 2 targeting."""
    tags = set()
    tech_tag_map = {
        "wordpress": ["wordpress", "wp-plugin", "wp-theme"],
        "nginx": ["nginx", "exposure"],
        "apache": ["apache"],
        "php": ["php"],
        "jquery": ["jquery", "xss"],
        # extend as needed
    }
    for tech in ctx.versioned_tech + ctx.nonversioned_tech:
        key = tech.name.lower()
        if key in tech_tag_map:
            tags.update(tech_tag_map[key])
    return list(tags)