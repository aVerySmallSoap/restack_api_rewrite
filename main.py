import uuid
from dotenv import load_dotenv
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from loguru import logger
from fastapi import FastAPI

from app.modules.pipeline.context import DiscoveryContext
from app.modules.utils.docker_utils import ensure_podman_docker_presence, stop_zap_service
from app.modules.tasks.pipeline import launch_pipeline
from app.modules.scanners.discovery.katana.katana import Katana


@asynccontextmanager
async def lifespan(app: FastAPI):
    # call and check docker images. Check if there is any updates
    logger.add("./app/logs/{time}.log", rotation="1 day", compression="zip")
    logger.info("Starting server")
    load_dotenv()
    try:
        ensure_podman_docker_presence()
    except Exception as e:
        logger.error(e)
        raise
    yield
    stop_zap_service()

app = FastAPI(lifespan=lifespan)

@app.get("/", summary="Testing enpoint for individual scanners")
async def root():
    session_id: str = str(uuid.uuid4())
    target = "http://10.89.0.3"
    # target = "https://his.dnsc.edu.ph"
    ctx: DiscoveryContext = DiscoveryContext(session_id=session_id, primary_url=target, primary_host=urlparse(target).netloc)
    katana = Katana()
    katana.start_scan(session_id, ctx)
    return {"session_id": session_id}

@app.get("/scan")
async def scan(url: str):
    session_id = str(uuid.uuid4())
    primary_host = urlparse(url).hostname
    assert isinstance(primary_host, str) # catch
    ctx = DiscoveryContext(
        session_id=session_id,
        primary_url=url,
        primary_host= primary_host
    )
    launch_pipeline(session_id, ctx)
    return {"session_id": session_id}  # client polls this ID for status