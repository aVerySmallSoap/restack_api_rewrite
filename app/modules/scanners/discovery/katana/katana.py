import json
import time
from pathlib import Path
import hashlib

from docker.models.containers import Container
from loguru import logger

from app.modules.pipeline.context import DiscoveryContext
from app.modules.interfaces.base import IHeadlessScanner
from app.modules.utils.utils import map_endpoints
from app.modules.utils.utils import is_same_host
from app.modules.scanners.discovery.katana.katana_context import KatanaContext

# TODO: add support for extracting fillable forms and elements
class Katana(IHeadlessScanner):
    _base_report_path: str = f"{Path.cwd()}/app/reports/katana"
    _prefix: str = "katana"
    _prefix_headless: str = "katana_headless"
    _scanner_context: KatanaContext
    # metrics
    _scan_start: float
    _scan_end: float


    def __init__(self): # This object should be gone after the scan
        self._scanner_context = KatanaContext()
        self._scan_start = time.time()

    def start_scan(self, session_id: str, ctx: DiscoveryContext) -> dict:
        logger.info(f"Starting Katana scan: {session_id}")
        self._scanner_context.primary_host = ctx.primary_host
        #Spawn necessary containers
        container: Container = self._spawn(session_id, ctx)
        headless_container: Container = self._spawn_headless(session_id, ctx)

        result = container.wait()
        headless_result = headless_container.wait()

        if result.get("StatusCode") != 0:
            logger.error(f"Katana has exited abruptly on exit code: {result.get('StatusCode')}")
            raise
        if headless_result.get("StatusCode") != 0: # crash
            logger.error(f"Headless Katana has exited abruptly on exit code: {result.get('StatusCode')}")
            raise
        return self._parse_results(session_id)

    def _parse_results(self, session_id: str) -> dict:
        logger.info(f"Parsing Katana results for session: {session_id}")
        hashed_records: list[str] = []
        endpoints: set = set()
        out_of_scope: set = set()

        try:
            assert isinstance(self._scanner_context.primary_host, str)
        except AssertionError as e:
            logger.error("The Katana context contains type errors!")
            logger.exception(e)
            raise

        # endpoint validation
        with open(f"{self._base_report_path}/{session_id}.json") as f:
            for line in f.read().splitlines():
                record = json.loads(line)
                record_hash = hashlib.sha256(line.encode('utf-8')).hexdigest()
                if not is_same_host(self._scanner_context.primary_host, record["request"].get("endpoint")):
                    out_of_scope.add(json)
                    continue
                hashed_records.append(record_hash)
                endpoints.add(record["request"].get("endpoint"))

        with open(f"{self._base_report_path}/headless_{session_id}.json") as f:
            for line in f.read().splitlines():
                record = json.loads(line)
                record_hash = hashlib.sha256(line.encode('utf-8')).hexdigest()
                if not is_same_host(self._scanner_context.primary_host, record["request"].get("endpoint")):
                    out_of_scope.add(json)
                    continue
                if record_hash not in hashed_records:
                    hashed_records.append(record_hash)
                endpoints.add(record["request"].get("endpoint"))
        site_map = map_endpoints(endpoints)
        self._scanner_context.content = {
            "siteMap": site_map,
            "outOfScope": out_of_scope,
        }
        self._cleanup(session_id)
        # test line
        logger.info(f"Time it took for the scan: {self._scan_end - self._scan_start}")
        # end test
        return self._scanner_context.content

    def _cleanup(self, session_id: str) -> None:
        import docker
        logger.info("Cleaning up Katana artifacts")

        Path(f"{self._base_report_path}/headless_{session_id}.json").unlink(missing_ok=True)
        Path(f"{self._base_report_path}/{session_id}.json").unlink(missing_ok=True)
        client = docker.from_env()
        try:
            container = client.containers.get(f"{self._prefix}_{session_id}")
            container.stop(timeout=5)
            container.remove()
            headless_container = client.containers.get(f"{self._prefix_headless}_{session_id}")
            headless_container.stop(timeout=5)
            headless_container.remove()
        except docker.errors.NotFound:
            logger.warning("Containers could not be found! Skipping cleanup...")
            return

    def _spawn(self, container_name: str, ctx: DiscoveryContext) -> Container:
        import docker
        logger.info(f"Spawning container: {self._prefix}_{container_name}")
        client = docker.from_env()
        return client.containers.run(
            image="projectdiscovery/katana",
            name=f"{self._prefix}_{container_name}",
            command=[
                "-or",
                "-ob",
                "-xhr",
                "-jc",
                "-kf", "all",
                "-rlm", "10",
                "-j",
                "-o", f"/reports/{container_name}.json",
                "-u", ctx.primary_url,
                "-silent",
            ],
            volumes={
                self._base_report_path: {
                    "bind": "/reports/",
                    "mode": "rw",
                }
            },
            detach=True,
            auto_remove=False,
        )

    def _spawn_headless(self, container_name: str, ctx: DiscoveryContext) -> Container:
        import docker
        logger.info(f"Spawning headless container: {self._prefix_headless}_{container_name}")
        client = docker.from_env()
        return client.containers.run(
            image="projectdiscovery/katana",
            name=f"{self._prefix_headless}_{container_name}",
            command=[
                "-headless",
                "-scp", self._scanner_context.headless_chrome_binary,
                "-nos",
                "-or",
                "-ob",
                "-xhr",
                "-jc",
                "-kf", "all",
                "-rlm", "10",
                "-j",
                "-o", f"/reports/headless_{container_name}.json",
                "-u", ctx.primary_url,
                "-silent",
            ],
            volumes={
                self._base_report_path: {
                    "bind": "/reports/",
                    "mode": "rw",
                }
            },
            detach=True,
            auto_remove=False,
        )