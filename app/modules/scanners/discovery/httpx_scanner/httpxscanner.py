import json
import time
from pathlib import Path

from docker.models.containers import Container
from loguru import logger

from app.modules.interfaces.types.context import TechEntry, ScanContext
from app.modules.interfaces.enums.scanners import IContainerScanner
from app.modules.interfaces.types.options import ScannerTaskResult
from app.modules.utils.utils import is_file_empty


class HttpxScanner(IContainerScanner):
    report_path = f"{Path.cwd()}/app/reports/httpx"
    scanner_name = "httpx"
    scanner_type = "container"

    def start_scan(self, session_id: str, ctx: ScanContext) -> dict:
        logger.info(f"Starting HTTPX scan: {session_id}")
        started = time.monotonic()
        try:
            container = self.spawn_container(session_id, ctx)
            result = container.wait()
            exit_code = result.get('StatusCode')
            logs = container.logs(stdout=True, stderr=True).decode(errors="replace")
            if exit_code != 0:
                logger.error(f"HTTPX has exited abruptly on exit code: {exit_code}")
                return ScannerTaskResult(
                    scanner="httpx",
                    phase="liveliness",
                    status="failed",
                    result=None,
                    error=f"httpx exited with code {exit_code}",
                    stdout=logs,
                    stderr=None,
                    exit_code=exit_code,
                    runtime_ms=(time.monotonic() - started) * 1_000,
                ).model_dump()

            parsed = self.parse_results(session_id)
            return ScannerTaskResult(
                scanner="httpx",
                phase="liveliness",
                status="success",
                result=parsed,
                stdout=logs,
                exit_code=exit_code,
                runtime_ms=(time.monotonic() - started) * 1_000,
            ).model_dump()
        except Exception as e:
            if "timeout" in str(e).lower():
                status = "timeout"
            else:
                status = "failed"
            return ScannerTaskResult(
                scanner="httpx",
                phase="liveliness",
                status=status,
                result=None,
                error=str(e),
                runtime_ms=(time.monotonic() - started) * 1_000,
            ).model_dump()

        finally:
            self.cleanup(session_id)

    #noinspection D
    def parse_results(self, session_id: str) -> dict | None:
        logger.info(f"Parsing HTTPX results for session: {session_id}")
        technologies_list: list[TechEntry] = []
        report_path = f"{self.report_path}/{session_id}.json"

        try:
            if is_file_empty(report_path):
                raise RuntimeWarning
            with open(report_path, "r") as f:
                for line in f.read().splitlines():
                    json_line: dict = json.loads(line) # I do not know yet if this will change into an array if multiple urls are fed
                    if json_line.get("failed"):
                        raise RuntimeWarning("httpx failed")
                    technologies = json_line.get("tech")
                    if not json_line:
                        continue # may be a break or return when empty. Need to test
                    if technologies:
                        for tech in technologies:
                            # each entry is a string with a structure of name:version
                            arr = tech.split(":") if tech.__contains__(":") else [tech]
                            if len(arr) == 1:
                                technologies_list.append(TechEntry(
                                    name=arr[0],
                                    version="",
                                    source="httpx"
                                ))
                                continue
                            technologies_list.append(TechEntry(
                                name=arr[0],
                                version=arr[1],
                                source="httpx"
                            ))
            cpe = json_line.get("cpe")
            if cpe is None:
                return {
                    "technologies": technologies_list,
                    "cpe": None,
                    "tls": json_line.get("tls"),
                }
            else:
                assert isinstance(cpe, list)
                return {
                    "technologies": technologies_list,
                    "cpe": [entry["cpe"] for entry in cpe],
                    "tls": json_line.get("tls"),
                }
        except RuntimeWarning:
            logger.warning("HTTPX report file empty! Was there any scanner errors?")
            return None
        except AssertionError:
            logger.exception("HTTPX parsing has encountered an unexpected type!")
            raise RuntimeError

    def cleanup(self, session_id: str) -> None:
        from docker import errors as docker_errors, from_env as docker_from_env
        logger.info("Cleaning up HTTPX artifacts")
        # Path(f"{self._base_report_path}/{session_id}.json").unlink(missing_ok=True)
        client = docker_from_env()
        try:
            container = client.containers.get(f"{self.scanner_name}_{session_id}")
            container.stop(timeout=5)
            container.remove()
        except docker_errors.NotFound:
            logger.warning(f"Could not find container with ID: {self.scanner_name}_{session_id}. Skipping cleanup")

    def spawn_container(self, session_id: str, ctx: ScanContext) -> Container:
        import docker
        logger.info(f"Spawning container: {self.scanner_name}_{session_id}")
        client = docker.from_env()
        return client.containers.run(
            image="projectdiscovery/httpx",
            name=f"{self.scanner_name}_{session_id}",
            command=[
                "-delay", "5s",
                "-pipeline",
                "-http2",
                "-sc",
                "-ct",
                "-jarm",
                "-server",
                "-td",
                "-method",
                "-ip",
                "-cdn",
                "-probe",
                "-tls-grab",
                "-irh",
                "-j",
                "-o", f"/reports/{session_id}.json",
                "-u", ctx.primary_url
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
        raise NotImplementedError