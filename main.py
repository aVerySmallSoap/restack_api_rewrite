import os
import time
import uuid
from dotenv import load_dotenv
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from loguru import logger
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import AnyUrl
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from app.modules.interfaces.types.context import ScanContext
from app.modules.utils.docker_utils import ensure_podman_docker_presence, stop_zap_service
from app.modules.tasks.pipeline import launch_full_pipeline, is_target_responsive
from app.modules.database.database import transaction
from app.modules.database.models.models import Scan
from app.modules.tasks.analytics.formal.formal_analytics import get_raw_vulnerabilities, calculate_time_series
from app.modules.generators.file_generators import generate_pdf, generate_excel
import app.modules.database.database # create database
from modules.tasks.pipeline import launch_quick_pipeline


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

@app.post("/v1/scan")
async def scan(url: str):
    session_id = str(uuid.uuid4())
    primary_host = urlparse(url).hostname
    ctx = ScanContext(
        session_id=session_id,
        primary_url=url,
        primary_host= primary_host,
        config=None
    )
    if not is_target_responsive(session_id, ctx):
        return {"status": "failed"} # Fail
    launch_full_pipeline(session_id, ctx)
    return {"session_id": session_id, "status": "success"}  # client polls this ID for status

@app.post("/v1/scan/quick")
async def quick_scan(url: str):
    session_id = str(uuid.uuid4())
    primary_host = urlparse(url).hostname
    ctx = ScanContext(
        session_id=session_id,
        primary_url=url,
        primary_host=primary_host,
        config=None
    )
    if not is_target_responsive(session_id, ctx):
        return {"status": "failed"}  # Fail
    launch_quick_pipeline(session_id, ctx)
    return {"session_id": session_id, "status": "success"}  # client polls this ID for status


@app.get("/v1/scan/result/{session_id}", description="Fetch a scan result by its session ID")
async def get_scan_result(session_id: str):
    """
    Fetch a scan result by its session ID
    :param session_id:
    :return: the whole scan suite
    """
    with (transaction() as db):
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

        return {"status": "success", "data": scan_db}

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
                    domain = parsed.netloc or parsed.path.split('/')[0]
                    # Remove port if present
                    domain = domain.split(':')[0]
                    if domain:
                        domains.add(domain)
                except Exception as e:
                    logger.warning(f"Failed to parse URL {url}: {e}")
                    continue

            return {
                "domains": sorted(list(domains)),
                "count": len(domains)
            }
    except Exception as e:
        logger.error(f"Failed to fetch analytics targets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/analytics/vulnerabilities")
async def get_vulnerabilities_list(
    target: str = Query(None),
    start: str = Query(None),
    end: str = Query(None),
    user_id: int = Query(None)
):
    """
    Get raw vulnerability list for the data table
    """
    try:
        return get_raw_vulnerabilities(
            target_domain=target,
            start_date=start,
            end_date=end,
            user_id=user_id
        )
    except Exception as e:
        logger.error(f"Failed to fetch vulnerability list: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/analytics/timeseries")
async def poll_data_timeseries(
    target: AnyUrl = Query(..., description="Target URL"),
    days: int = 90,
    start: str = Query(None, description="Start date (YYYY-MM-DD)"),
    end: str = Query(None, description="End date (YYYY-MM-DD)")
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
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
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
        media_type="application/pdf"
    )


@app.get("/v1/history")
def get_scan_history():
    pass