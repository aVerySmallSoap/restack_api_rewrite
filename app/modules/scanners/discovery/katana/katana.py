import json
import time
from pathlib import Path
import hashlib
from time import sleep

from docker.models.containers import Container
from loguru import logger

from app.modules.pipeline.context import ScanContext
from app.modules.utils.utils import map_endpoints, is_same_host
from app.modules.scanners.discovery.katana.katana_context import KatanaContext
from app.modules.interfaces.enums.scanners import IContainerScanner
from app.modules.interfaces.types.options import ScannerTaskResult

class Katana(IContainerScanner):
    report_path = f"{Path.cwd()}/app/reports/katana"
    scanner_name = "katana"
    scanner_type = "container"
    _scanner_context: KatanaContext
    _timeout=600

    def __init__(self):
        self._scanner_context = KatanaContext()

    def start_scan(self, session_id: str, ctx: ScanContext) -> dict:
        logger.info(f"Starting Katana scan: {session_id}")
        started = time.monotonic()
        try:
            self._scanner_context.primary_host = ctx.primary_host
            container = self.spawn_container(session_id, ctx)
            container_result = container.wait(timeout=self._timeout)
            if container.status == "running": # do not launch a headless scan when not finished
               sleep(10)
            headless_container = self.spawn_headless_container(session_id, ctx)
            headless_result = headless_container.wait(timeout=self._timeout)
            exit_code = container_result.get("StatusCode")
            headless_exit_code = headless_result.get("StatusCode")

            assert isinstance(container, Container) and isinstance(headless_container, Container)

            logs = container.logs(stdout=True, stderr=True).decode(errors="replace")
            headless_logs = headless_container.logs(stdout=True, stderr=True).decode(errors="replace")

            if exit_code != 0 or headless_exit_code != 0:
                logger.error(f"Katana has exited abruptly on exit code: {exit_code}")
                return ScannerTaskResult(
                    scanner="katana",
                    phase="preamble",
                    status="failed",
                    result=None,
                    error=f"Katana exited with code {exit_code}",
                    stdout=[logs, headless_logs],
                    stderr=None,
                    exit_code=exit_code,
                    runtime_ms=int((time.monotonic() - started) * 1000),
                ).model_dump()

            parsed = self.parse_results(session_id)
            return ScannerTaskResult(
                scanner="katana",
                phase="preamble",
                status="success",
                result=parsed,
                stdout=[logs, headless_logs],
                exit_code=exit_code,
                runtime_ms=int((time.monotonic() - started) * 1000),
            ).model_dump()

        except Exception as e:
            if "timeout" in str(e).lower():
                status = "timeout"
            else:
                status = "failed"
            return ScannerTaskResult(
                scanner="katana",
                phase="preamble",
                status=status,
                result=None,
                error=str(e),
                runtime_ms=int((time.monotonic() - started) * 1000),
            ).model_dump()

        finally:
            self.cleanup(session_id)

    def parse_results(self, session_id: str) -> dict:
        logger.info(f"Parsing Katana results for session: {session_id}")
        hashed_records: list[str] = []
        out_of_scope: list = []
        unique_endpoints: set = set()
        endpoints: list[str] = []

        try:
            assert isinstance(self._scanner_context.primary_host, str)
        except AssertionError as e:
            logger.error("The Katana context contains type errors!")
            logger.exception(e)
            raise

        # endpoint validation
        with open(f"{self.report_path}/{session_id}.json") as f:
            for line in f.read().splitlines():
                record = json.loads(line)
                _endpoint = record["request"].get("endpoint")
                record_hash = hashlib.sha256(line.encode('utf-8')).hexdigest()
                if not is_same_host(self._scanner_context.primary_host, _endpoint):
                    out_of_scope.append(_endpoint)
                    continue
                hashed_records.append(record_hash)
                endpoints.append(_endpoint)
                unique_endpoints.add(_endpoint)

        with open(f"{self.report_path}/headless_{session_id}.json") as f:
            for line in f.read().splitlines():
                record = json.loads(line)
                _endpoint = record["request"].get("endpoint")
                record_hash = hashlib.sha256(line.encode('utf-8')).hexdigest()
                if not is_same_host(self._scanner_context.primary_host, _endpoint):
                    out_of_scope.append(_endpoint)
                    continue
                if record_hash not in hashed_records:
                    hashed_records.append(record_hash)
                endpoints.append(_endpoint)
                unique_endpoints.add(_endpoint)
        site_map = map_endpoints(unique_endpoints)
        content = {
            "siteMap": site_map,
            "endPoints": endpoints,
            "outOfScope": out_of_scope,
        }
        self._scanner_context.content = content
        self.cleanup(session_id)
        return content

    def cleanup(self, session_id: str) -> None:
        import docker
        logger.info("Cleaning up Katana artifacts")

        Path(f"{self.report_path}/headless_{session_id}.json").unlink(missing_ok=True)
        Path(f"{self.report_path}/{session_id}.json").unlink(missing_ok=True)
        client = docker.from_env()
        try:
            container = client.containers.get(f"{self.scanner_name}_{session_id}")
            container.stop(timeout=5)
            container.remove()
            headless_container = client.containers.get(f"{self.scanner_name}_headless_{session_id}")
            headless_container.stop(timeout=5)
            headless_container.remove()
        except docker.errors.NotFound:
            logger.warning("Containers could not be found! Skipping cleanup...")
            return
    
    def spawn_container(self, session_id: str, ctx: ScanContext) -> Container:
        import docker
        logger.info(f"Spawning katana container: {self.scanner_name}_{session_id}")
        client = docker.from_env()
        return client.containers.run(
            image="projectdiscovery/katana",
            name=f"{self.scanner_name}_{session_id}",
            command=[
                "-or",
                "-ob",
                "-xhr",
                "-jc",
                "-kf", "all",
                "-rlm", "10",
                "-j",
                "-o", f"/reports/{session_id}.json",
                "-u", ctx.primary_url,
                "-silent",
                # "-H", "Cookie: MoodleSession=81gki0uugm6qig6g1lc2kvc68t",
                # "-fr", "(?i)logout"
            ],
            volumes={
                self.report_path: {
                    "bind": "/reports/",
                    "mode": "rw",
                }
            },
            detach=True,
            auto_remove=False,
        )

    def spawn_headless_container(self, session_id: str, ctx: ScanContext) -> Container:
        import docker
        logger.info(
            f"Spawning katana headless container: {self.scanner_name}_headless_{session_id}")
        client = docker.from_env()
        return client.containers.run(
            image="projectdiscovery/katana",
            name=f"{self.scanner_name}_headless_{session_id}",
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
                "-o", f"/reports/headless_{session_id}.json",
                "-u", ctx.primary_url,
                "-silent",
                # "-H", "Cookie: MoodleSession=81gki0uugm6qig6g1lc2kvc68t",
                # "-fr", "(?i)logout"
            ],
            volumes={
                self.report_path: {
                    "bind": "/reports/",
                    "mode": "rw",
                }
            },
            detach=True,
            auto_remove=False,
        )
