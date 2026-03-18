import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.modules.pipeline.context import DiscoveryContext
from app.modules.scanners.discovery.httpx.httpx import HTTPX
from app.modules.utils.docker_utils import check_and_update_images
from app.modules.scanners.discovery.subfinder.subfinder import Subfinder
from app.modules.scanners.discovery.whatweb.whatweb import WhatWeb
from app.modules.scanners.discovery.sslyze.sslyze import SSLyze
from app.modules.scanners.discovery.wappalyzer_next.wappalyzer_next import WappalyzerNext

# Injectables
httpx = HTTPX()
subfinder = Subfinder()
whatweb = WhatWeb()
sslyze = SSLyze()
wappalyzer_next = WappalyzerNext()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # call and check docker images. Check if there is any updates
    print("Starting server with checks")
    await check_and_update_images()
    yield

app = FastAPI(lifespan=lifespan)

@app.get("/")
async def root():
    ctx: DiscoveryContext = DiscoveryContext
    ctx.primary_url = "https://dnsc.edu.ph"
    test_id: str = str(uuid.uuid4())
    # httpx.start_scan(test_id, ctx)
    # print(subfinder.start_scan(test_id, ctx))
    # whatweb.start_scan(test_id, ctx)
    # sslyze.start_scan(test_id, ctx)
    wappalyzer_next.start_scan(test_id, ctx)
    return {"message": "Hello World"}