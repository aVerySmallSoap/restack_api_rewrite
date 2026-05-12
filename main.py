import time
import uuid
from dotenv import load_dotenv
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from loguru import logger
from fastapi import FastAPI

from app.modules.interfaces.types.context import ScanContext
from app.modules.utils.docker_utils import ensure_podman_docker_presence, stop_zap_service
from app.modules.tasks.pipeline import launch_pipeline
from app.modules.tasks.pipeline import is_target_responsive
import app.modules.database.database # create database


@asynccontextmanager
async def lifespan(app: FastAPI):
    # call and check docker images. Check if there is any updates
    start_time = time.time()
    logger.add("./app/logs/{time}.log", rotation="1 day", compression="zip")
    logger.info("Starting server")
    load_dotenv()
    try:
        ensure_podman_docker_presence()
    except Exception as e:
        logger.error(e)
        raise
    end_time = time.time()
    logger.debug(f"Startup time: {(end_time - start_time)}")
    yield
    stop_zap_service()

app = FastAPI(lifespan=lifespan)

@app.get("/scan")
async def scan(url: str):
    session_id = str(uuid.uuid4())
    primary_host = urlparse(url).hostname
    assert isinstance(primary_host, str) # catch
    ctx = ScanContext(
        session_id=session_id,
        primary_url=url,
        primary_host= primary_host,
        config=None
    )
    if not is_target_responsive(session_id, ctx):
        return {"status": "failed"} # Fail
    launch_pipeline(session_id, ctx)
    return {"session_id": session_id, "status": "success"}  # client polls this ID for status