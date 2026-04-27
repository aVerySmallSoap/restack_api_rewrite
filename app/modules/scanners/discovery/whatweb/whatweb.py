import json
import time
from pathlib import Path

from docker.models.containers import Container
from loguru import logger

from modules.interfaces.types.context import ScanContext, TechEntry
from app.modules.interfaces.enums.scanners import IContainerScanner
from app.modules.interfaces.types.options import ScannerTaskResult


# noinspection D
class WhatWeb(IContainerScanner):
    report_path = f"{Path.cwd()}/app/reports/whatweb"
    scanner_name = "whatweb"
    scanner_type = "container"
    _timeout=300

    def start_scan(self, session_id: str, ctx: ScanContext) -> dict:
        logger.info(f"Starting WhatWeb scan: {session_id}")
        started = time.monotonic()
        try:
            container = self.spawn_container(session_id, ctx)
            result = container.wait(timeout=self._timeout)
            exit_code = result.get("StatusCode")
            logs = container.logs(stdout=True, stderr=True).decode(errors="replace")

            if exit_code != 0:
                logger.debug(f"WhatWeb exited abruptly! Exit code: {exit_code}")
                return ScannerTaskResult(
                    scanner="whatweb",
                    phase="asset",
                    status="failed",
                    result=None,
                    error=f"WhatWeb exited with code {exit_code}",
                    stdout=logs,
                    stderr=None,
                    exit_code=exit_code,
                    runtime_ms=int((time.monotonic() - started) * 1000),
                ).model_dump()

            parsed = self.parse_results(session_id)
            return ScannerTaskResult(
                scanner="whatweb",
                phase="asset",
                status="success",
                result=parsed,
                stdout=logs,
                exit_code=exit_code,
                runtime_ms=int((time.monotonic() - started) * 1000),
            ).model_dump()

        except Exception as e:
            if "timeout" in str(e).lower():
                status = "timeout"
            else:
                status = "failed"
            return ScannerTaskResult(
                scanner="whatweb",
                phase="asset",
                status=status,
                result=None,
                error=str(e),
                runtime_ms=int((time.monotonic() - started) * 1000),
            ).model_dump()

        finally:
            # self.cleanup(session_id)
            pass

    def parse_results(self, session_id: str) -> dict:
        logger.info(f"Parsing WhatWeb results for session: {session_id}")
        _excluded = ["UncommonHeaders", "Open-Graph-Protocol", "Title", "Frame", "Script", "HTML5"]
        _trivial = ["Email", "Script", "IP", "Country", "HTTPServer"]
        _tech: list[TechEntry] = []
        _cookies = []
        _extra = []
        with open(f"{self.report_path}/{session_id}.json", "r+") as f:
            report = json.load(f)
            if len(report) <= 0 or report is None:
                return None
            for plugin, content in report[0]["plugins"].items():
                if content is None or plugin in _excluded:
                    continue
                if plugin == "MetaGenerator" and len(content) > 0:
                    self._parse_meta_generator(content["string"], _tech)
                    continue
                if plugin in _trivial:
                    _extra.append({plugin: content["string"]})
                    continue
                if plugin == "Cookies":  # Handle cookies differently
                    _cookies.append({plugin: content["string"]})
                    continue
                _version = content.get("version", None)
                if _version is not None:
                    if len(_version) > 1:
                        for _ in _version:
                            _tech.append(TechEntry(
                                name=plugin,
                                version=_,
                                source="whatweb",
                                categories=None
                            ))
                    elif len(content["version"]) == 1:
                        _tech.append(
                            TechEntry(
                                name=plugin,
                                version=_version[0],
                                source="whatweb",
                                categories=None
                            )
                        )
                else:
                    _tech.append(
                        TechEntry(
                            name=plugin,
                            version=None,
                            source="whatweb",
                            categories=None
                        )
                    )
        self.cleanup(session_id)
        return {
            "technologies": [entry.model_dump() for entry in _tech],
            "cookies": _cookies,
            "extra": _extra,
        }

    def cleanup(self, session_id: str) -> None:
        import docker
        logger.info("Cleaning up WhatWeb artifacts")
        # Path(f"{self._base_report_path}/{session_id}.json").unlink(missing_ok=True)
        client = docker.from_env()
        try:
            container = client.containers.get(f"{self.scanner_name}_{session_id}")
            container.stop(timeout=5)
            container.remove()
        except docker.errors.NotFound:
            logger.warning(f"Could not find container with ID: {self.scanner_name}_{session_id}. Skipping cleanup")

    def spawn_container(self, session_id: str, ctx: ScanContext) -> Container:
        import docker
        logger.info(f"Spawning container: {self.scanner_name}_{session_id}")
        client = docker.from_env()
        return client.containers.run(
            image="localhost/whatweb",
            name=f"{self.scanner_name}_{session_id}",
            command=[
                "./whatweb",
                "-a", "3",
                "--log-json", f"/reports/{session_id}.json",
                ctx.primary_url
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

    @staticmethod
    def _parse_meta_generator(meta_data: dict, technologies: list):
        for item in meta_data:
            _plugin = ""
            _version = ""
            for index in range(len(item)):
                if item[index] == ";":  # Edge case of Tech_name version; wherein the tech is displayed with features
                    break
                if item[index].isdigit() or item[index] == ".":
                    _version += item[index]
                elif item[index] != len(item) - 1:
                    _plugin += item[index]
            technologies.append(
                TechEntry(
                    name=_plugin,
                    version=_version if _version != "" else None,
                    source="whatweb",
                    categories=None
                )
            )