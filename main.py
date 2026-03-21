import uuid
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from loguru import logger
from fastapi import FastAPI

from app.modules.pipeline.context import DiscoveryContext
from app.modules.scanners.discovery.httpx_scanner.httpx_scanner import HTTPX_SCANNER
from app.modules.utils.docker_utils import check_and_update_images
from app.modules.scanners.discovery.subfinder.subfinder import Subfinder
from app.modules.scanners.discovery.whatweb.whatweb import WhatWeb
from app.modules.scanners.discovery.sslyze.sslyze import SSLyze
from app.modules.scanners.discovery.wappalyzer_next.wappalyzer_next import WappalyzerNext
from app.modules.scanners.discovery.katana.katana import Katana
from app.modules.interfaces.enums.options import KatanaContext
from app.modules.tasks.pipeline import launch_pipeline

# Injectables
httpx_scanner = HTTPX_SCANNER()
subfinder = Subfinder()
whatweb = WhatWeb()
sslyze = SSLyze()
wappalyzer_next = WappalyzerNext()
katana = Katana()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # call and check docker images. Check if there is any updates
    logger.add("./app/logs/{time}.log", rotation="1 day", compression="zip")
    logger.info("Starting server")
    await check_and_update_images()
    yield

app = FastAPI(lifespan=lifespan)

@app.get("/")
async def root():
    session_id: str = str(uuid.uuid4())
    target = "https://dnsc.edu.ph"
    ctx: DiscoveryContext = DiscoveryContext(session_id=session_id, primary_url=target, primary_host=urlparse(target).netloc)
    # httpx_scanner.start_scan(test_id, ctx)
    # subfinder.start_scan(test_id, ctx)
    # whatweb.start_scan(test_id, ctx)
    # sslyze.start_scan(test_id, ctx)
    # wappalyzer_next.start_scan(test_id, ctx)
    katana.start_scan(session_id, ctx, KatanaContext(session_id=session_id, is_two_pass=True))
    return {"session_id": session_id}

@app.get("/scan")
async def scan(url: str):
    session_id = str(uuid.uuid4())
    ctx = DiscoveryContext(
        session_id=session_id,
        primary_url=url,
        primary_host=urlparse(url).hostname,
    )
    launch_pipeline(session_id, ctx)
    return {"session_id": session_id}  # client polls this ID for status