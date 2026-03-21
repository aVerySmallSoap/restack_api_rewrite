import json

from celery import shared_task
from app.modules.pipeline.context import DiscoveryContext, TechEntry, BannerEntry, TLSFinding, SiteMap
from app.modules.scanners.discovery.subfinder.subfinder import Subfinder
from app.modules.scanners.discovery.httpx_scanner.httpx_scanner import HTTPX_SCANNER
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
    return {"type": "katana", "result": Katana().start_scan(session_id, ctx)}

@celery_app.task(bind=True)
def task_httpx(self, session_id: str, ctx_json: str) -> dict:
    ctx = DiscoveryContext(**json.loads(ctx_json))
    return {"type": "httpx", "result": HTTPX_SCANNER().start_scan(session_id, ctx)}

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
def build_discovery_context(self, results: list[dict], session_id: str, ctx_json: str) -> str:
    """
    Chord callback — fires after all Phase 1 tasks finish.
    Merges all scanner results into DiscoveryContext and saves to Redis.
    Returns ctx_json for the next phase in the chain.
    """
    ctx = DiscoveryContext(**json.loads(ctx_json))

    for item in results:
        match item["type"]:
            case "subfinder":
                # item["result"] is {host: {hosts: [...], sources: {...}}}
                if item["result"] is None or item["result"].values() == {}:
                    break
                for host_data in item["result"].values():
                    ctx.live_hosts.extend(host_data.get("hosts", []))

            case "httpx":
                if item["result"] is None or item["result"].values() == {}:
                    break
                for host, banner_data in item["result"].get("banners", {}).items():
                    ctx.banners[host] = BannerEntry(**banner_data)
                ctx.has_https = item["result"].get("has_https", False)

            case "sslyze":
                if item["result"] is None or item["result"].values() == {}:
                    break
                for finding in item["result"].get("tls_findings", []):
                    ctx.tls_findings.append(TLSFinding(**finding))

            case "whatweb" | "wappalyzer":
                if item["result"] is None or item["result"].values() == {}:
                    break
                for tech in item["result"].get("versioned", []):
                    ctx.versioned_tech.append(TechEntry(**tech))
                for tech in item["result"].get("nonversioned", []):
                    ctx.nonversioned_tech.append(TechEntry(**tech))

            case "katana":
                if item["result"] is None or item["result"].values() == {}:
                    break
                ctx.site_map = SiteMap(
                    collection=item["result"].get("collection", []),
                    map=item["result"].get("site_map", {})
                )

    # Derive nuclei tags from detected tech before saving
    ctx.nuclei_tags = _derive_nuclei_tags(ctx)
    ctx.save_to_redis()

    return ctx.to_json()  # passed into Phase 2 chain


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