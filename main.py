import asyncio
import os
import time
import uuid
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from loguru import logger
from pydantic import AnyUrl
from sqlalchemy import and_, select
from sqlalchemy.orm import joinedload
from starlette.websockets import WebSocketDisconnect

import app.modules.database.database  # create database
from app.modules.database.database import async_engine, async_transaction, transaction
from app.modules.database.models.base import Base
from app.modules.database.models.models import Scan, ScanPhaseProgress
from app.modules.generators.file_generators import generate_excel, generate_pdf
from app.modules.interfaces.enums.scan_tracking import ScanProgress
from app.modules.interfaces.types.context import ScanContext, redis_client
from app.modules.interfaces.types.requests import ScanRequest
from app.modules.tasks.analytics.formal.formal_analytics import (
    calculate_time_series,
    get_raw_vulnerabilities,
)
from app.modules.tasks.pipeline import (
    is_target_responsive,
    launch_full_pipeline,
    launch_quick_pipeline,
)
from app.modules.utils.docker_utils import (
    ensure_podman_docker_presence,
    stop_zap_service,
)
from app.modules.utils.websockets import connection_manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    # call and check docker images. Check if there is any updates
    start_time = time.time()
    logger.add("./app/logs/{time}.log", rotation="1 day", compression="zip")
    logger.info("Starting server")
    load_dotenv()
    try:
        ensure_podman_docker_presence()
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as e:
        logger.error(e)
        raise
    end_time = time.time()
    logger.debug(f"Startup time: {(end_time - start_time)}")
    yield
    stop_zap_service()


app = FastAPI(lifespan=lifespan)


origins = [
    "*"  # Allows all origins
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/v1/scan")
async def scan(request: ScanRequest):
    session_id = str(uuid.uuid4())
    primary_host = urlparse(request.url).hostname
    ctx = ScanContext(
        session_id=session_id,
        primary_url=request.url,
        primary_host=primary_host,
        config=None,
    )
    if not is_target_responsive(session_id, ctx):
        return {"status": "failed"}  # Fail
    launch_full_pipeline(session_id, request.user_id, ctx)
    return {
        "session_id": session_id,
        "status": "success",
    }  # client polls this ID for status


@app.post("/v1/scan/quick")
async def quick_scan(request: ScanRequest):
    session_id = str(uuid.uuid4())
    primary_host = urlparse(request.url).hostname
    ctx = ScanContext(
        session_id=session_id,
        primary_url=request.url,
        primary_host=primary_host,
        config=None,
    )
    if not is_target_responsive(session_id, ctx):
        return {"status": "failed"}  # Fail
    launch_quick_pipeline(session_id, request.user_id, ctx)
    return {
        "session_id": session_id,
        "status": "success",
    }  # client polls this ID for status


@app.get(
    "/v1/scan/result/{session_id}", description="Fetch a scan result by its session ID"
)
async def get_scan_result(session_id: str):
    """
    Fetch a scan result by its session ID
    :param session_id:
    :return: the whole scan suite
    """
    with transaction() as db:
        stmt = (
            select(Scan)
            .options(
                joinedload(Scan.vulnerabilities),
                joinedload(Scan.technologies),
                joinedload(Scan.report),
            )
            .where(Scan.id == session_id)
        )
        scan_db = db.execute(stmt).scalars().unique().one_or_none()
        if scan_db is None:
            return {"status": "failed", "reason": "Scan does not exist!"}

        raw_discovery = redis_client.get(f"discovery:{session_id}")
        raw_attack = redis_client.get(f"attack:{session_id}")
        return {
            "status": "success",
            "data": scan_db,
            "discovery": raw_discovery,
            "attack": raw_attack,
        }


@app.get("/v1/analytics/targets")
async def get_analytics_targets():
    """Get list of all unique target domains from scans"""
    try:
        with transaction() as db:
            # Get all unique target URLs
            target_urls = db.query(Scan.target_url).distinct().all()

            # Extract domains from URLs
            domains = set()
            for url_tuple in target_urls:
                url = url_tuple[0]
                try:
                    parsed = urlparse(url)
                    # Get netloc (hostname with port if present)
                    domain = parsed.netloc or parsed.path.split("/")[0]
                    # Remove port if present
                    domain = domain.split(":")[0]
                    if domain:
                        domains.add(domain)
                except Exception as e:
                    logger.warning(f"Failed to parse URL {url}: {e}")
                    continue

            return {"domains": sorted(list(domains)), "count": len(domains)}
    except Exception as e:
        logger.error(f"Failed to fetch analytics targets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/analytics/vulnerabilities")
async def get_vulnerabilities_list(
    target: str = Query(None),
    start: str = Query(None),
    end: str = Query(None),
    user_id: int = Query(None),
):
    """
    Get raw vulnerability list for the data table
    """
    try:
        return get_raw_vulnerabilities(
            target_domain=target, start_date=start, end_date=end, user_id=user_id
        )
    except Exception as e:
        logger.error(f"Failed to fetch vulnerability list: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/analytics/timeseries")
async def poll_data_timeseries(
    target: AnyUrl = Query(..., description="Target URL"),
    days: int = 90,
    start: str = Query(None, description="Start date (YYYY-MM-DD)"),
    end: str = Query(None, description="End date (YYYY-MM-DD)"),
):
    return calculate_time_series(target, days, start_date=start, end_date=end)


@app.get("/v1/report/{report_id}/export/excel")
async def export_excel(report_id: str):
    """Generates and downloads the Excel report"""
    result = generate_excel(report_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])

    return FileResponse(
        result["path"],
        filename=os.path.basename(result["path"]),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.get("/v1/report/{report_id}/export/pdf")
async def export_pdf(report_id: str):
    """Generates and downloads the PDF report"""
    result = generate_pdf(report_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])

    return FileResponse(
        result["path"],
        filename=os.path.basename(result["path"]),
        media_type="application/pdf",
    )


# noinspection D
@app.websocket("/v1/ws/scans/poll")
async def poll_scans(websocket: WebSocket):
    await connection_manager.connect(websocket)
    previous_scans = {}  # Track previous state

    try:
        while True:
            await asyncio.sleep(5)  # Poll database every 5 seconds
            try:
                # Use asyncio.to_thread because database access is blocking
                results = {}
                async with async_transaction() as db:
                    stmt = select(Scan, ScanPhaseProgress).join(
                        ScanPhaseProgress,
                        and_(
                            ScanPhaseProgress.scan_id == Scan.id,
                            ScanPhaseProgress.progress != ScanProgress.ERROR,
                        ),
                    )

                    rows = (await db.execute(stmt)).all()

                    for scan, progress in rows:
                        results[str(scan.id)] = {
                            "session": str(scan.id),
                            "target": scan.target_url,
                            "step": progress.progress,
                        }

                # Check for completed scans (were in previous_scans but not in current)
                if previous_scans:
                    for session_id in previous_scans:
                        if session_id not in results:
                            # Scan completed, send final notification
                            await websocket.send_json(
                                {
                                    "completed": {
                                        session_id: {
                                            "session": session_id,
                                            "step": "Completed",
                                            "message": "Scan finished successfully",
                                        }
                                    }
                                }
                            )

                if not results:
                    await websocket.send_json({"message": "No active scans"})
                else:
                    await websocket.send_json(results)

                # Update previous state
                previous_scans = results.copy()

            except WebSocketDisconnect:
                # Client disconnected during send, break the loop
                logger.info("WebSocket client disconnected during polling")
                raise  # Re-raise to be caught by outer handler
            except ConnectionError as e:
                # WebSocket connection error, break the loop
                logger.info(f"WebSocket connection error: {e}")
                break
            except Exception as e:
                # Log database or other errors but continue polling
                logger.error(f"Error polling active scans: {e}", exc_info=True)
                try:
                    await websocket.send_json(
                        {"error": "Failed to fetch scans", "message": str(e)}
                    )
                except Exception as e:
                    logger.warning(
                        "Could not send error to client, connection may be closed"
                    )
                    logger.error(e)
                    break

    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    except Exception as e:
        logger.error(f"Unexpected WebSocket error: {e}", exc_info=True)
    finally:
        # Safely disconnect, catching any errors
        try:
            connection_manager.disconnect(websocket)
        except Exception as e:
            logger.warning(f"Error during WebSocket disconnect: {e}")


@app.get("/v1/history")
def get_scan_history():
    pass
