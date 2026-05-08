import time
from pathlib import Path

from loguru import logger
from docker.models.containers import Container

from app.modules.interfaces.types.context import ScanContext, TechEntry
from modules.interfaces.scanners import IContainerScanner
from app.modules.interfaces.types.options import ScannerTaskResult
from app.modules.utils.utils import is_file_empty


# noinspection D
class WappalyzerNext(IContainerScanner):
    report_path = f"{Path.cwd()}/app/reports/wappalyzer_next"
    scanner_name = "wappalyzer-next"
    scanner_type = "container"
    _scanner_context: ScanContext
    _timeout=300

    def start_scan(self, session_id: str, ctx: ScanContext) -> dict:
        logger.info(f"Starting Wappalyzer Next scan: {session_id}")
        started = time.monotonic()

        try:
            self._scanner_context = ctx
            container = self.spawn_container(session_id, ctx)
            container_result = container.wait(timeout=self._timeout)
            if container.status == "running": # do not launch a headless scan when not finished
               time.sleep(10)
            headless_container = self.spawn_headless_container(session_id, ctx)
            headless_result = headless_container.wait(timeout=self._timeout)
            exit_code = container_result.get("StatusCode")
            headless_exit_code = headless_result.get("StatusCode")

            assert isinstance(container, Container) and isinstance(headless_container, Container)

            logs = container.logs(stdout=True, stderr=True).decode(errors="replace")
            headless_logs = headless_container.logs(stdout=True, stderr=True).decode(errors="replace")

            if exit_code != 0 or headless_exit_code != 0:
                logger.error(f"Wappalyzer-next has exited abruptly on exit code: {exit_code}")
                return ScannerTaskResult(
                    scanner="wappalyzer-next",
                    phase="asset",
                    status="failed",
                    result=None,
                    error=f"wappalyzer-next exited with code {exit_code}",
                    stdout=[logs, headless_logs],
                    stderr=None,
                    exit_code=exit_code,
                    runtime_ms=(time.monotonic() - started) * 1_000,
                ).model_dump()

            parsed = self.parse_results(session_id)
            return ScannerTaskResult(
                scanner="wappalyzer-next",
                phase="asset",
                status="success",
                result=parsed,
                stdout=[logs, headless_logs],
                exit_code=exit_code,
                runtime_ms=(time.monotonic() - started) * 1_000,
            ).model_dump()

        except Exception as e:
            logger.exception(e)
            if "timeout" in str(e).lower():
                status = "timeout"
            else:
                status = "failed"
            return ScannerTaskResult(
                scanner="wappalyzer-next",
                phase="asset",
                status=status,
                result=None,
                error=str(e),
                runtime_ms=(time.monotonic() - started) * 1_000,
            ).model_dump()

        finally:
            self.cleanup(session_id)

    def parse_results(self, session_id: str) -> dict | None:
        import json
        logger.info(f"Parsing wappalyzer-next results for session: {session_id}")
        path = f"{self.report_path}/{session_id}.json"
        headless_path = f"{self.report_path}/headless_{session_id}.json"
        paths = [path, headless_path]
        collection: list[TechEntry] = []

        try:
            for index in range(len(paths)):
                if is_file_empty(paths[index]):
                    if index == len(paths) - 1:
                        raise RuntimeWarning
                    continue
                with open(paths[index], "r") as file:
                    for line in file.read().splitlines():
                        record = json.loads(line).get(self._scanner_context.primary_url)
                        if record is not None or record != {}:
                            assert isinstance(record, dict)
                            for plugin, content in record.items():
                                collection.append(
                                    TechEntry(
                                        name=plugin,
                                        version=content["version"] if content["version"] != "" else None,
                                        source="wappalyzer-next",
                                        categories=None
                                    )
                                )
                return {
                    "technologies": collection
                }
        except RuntimeWarning:
            logger.warning("Wappalyzer-next report file empty! Was there any scanner errors?")
            return None
        except AssertionError as e:
            logger.error("Wappalyzer-next parsing has encountered an unexpected type!")
            logger.exception(e)
            raise RuntimeError

    def cleanup(self, session_id: str) -> None:
        import docker
        logger.info("Cleaning up wappalyzer-next artifacts")
        # Path(f"{self._base_report_path}/{session_id}.json").unlink(missing_ok=True)
        client = docker.from_env()
        try:
            container = client.containers.get(f"{self.scanner_name}_{session_id}")
            container.stop(timeout=5)
            container.remove()
            container = client.containers.get(f"{self.scanner_name}_headless_{session_id}")
            container.stop(timeout=5)
            container.remove()
        except docker.errors.NotFound:
            logger.warning(f"Could not find container with ID: {self.scanner_name}_{session_id}. Skipping cleanup")

    def spawn_container(self, session_id: str, ctx: ScanContext) -> Container:
        import docker
        logger.info(f"Spawning container: {self.scanner_name}_{session_id}")
        client = docker.from_env()
        return client.containers.run(
            image="iamyourdev/wappalyzer:latest",
            name=f"{self.scanner_name}_{session_id}",
            command=[
                "--scan-type", "balanced",
                "-oJ", f"/reports/{session_id}.json",
                "-i", ctx.primary_url
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
        logger.info(f"Spawning container: {self.scanner_name}_headless_{session_id}")
        client = docker.from_env()
        return client.containers.run(
            image="iamyourdev/wappalyzer:latest",
            name=f"{self.scanner_name}_headless_{session_id}",
            command=[
                "--scan-type", "full",
                "-oJ", f"/reports/headless_{session_id}.json",
                "-i", ctx.primary_url
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