import uuid
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from loguru import logger
from fastapi import FastAPI

from app.modules.pipeline.context import DiscoveryContext
from app.modules.utils.docker_utils import check_and_update_images
from app.modules.tasks.pipeline import launch_pipeline
from app.modules.scanners.web.wapiti.wapiti_scanner import WapitiScanner


@asynccontextmanager
async def lifespan(app: FastAPI):
    # call and check docker images. Check if there is any updates
    logger.add("./app/logs/{time}.log", rotation="1 day", compression="zip")
    logger.info("Starting server")
    check_and_update_images()
    yield

app = FastAPI(lifespan=lifespan)

@app.get("/")
async def root():
    session_id: str = str(uuid.uuid4())
    target = "https://dnsc.edu.ph"
    ctx: DiscoveryContext = DiscoveryContext(session_id=session_id, primary_url=target, primary_host=urlparse(target).netloc)
    wapiti = WapitiScanner()
    wapiti.start_scan(session_id, ctx)
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