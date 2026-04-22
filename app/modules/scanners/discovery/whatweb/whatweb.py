import json
from pathlib import Path

from docker.models.containers import Container
from loguru import logger

from app.modules.pipeline.context import ScanContext
from app.modules.interfaces.base import IHeadlessScanner
from app.modules.pipeline.context import TechEntry


# noinspection D
class WhatWeb(IHeadlessScanner):
    _base_report_path: str = f"{Path.cwd()}/app/reports/whatweb"
    _prefix = "whatweb"

    def start_scan(self, session_id: str, ctx: ScanContext) -> dict:
        logger.info(f"Starting WhatWeb scan: {session_id}")
        container = self._spawn(session_id, ctx)

        result = container.wait()
        exit_code = result["StatusCode"]

        if exit_code != 0:
            logger.debug(f"WhatWeb exited abruptly! Exit code: {exit_code}")
            container.remove()
            raise RuntimeError(f"WhatWeb failed with exit code {exit_code}")
        container.remove()
        return self._parse_results(session_id)

    def _parse_results(self, session_id: str) -> dict:
        logger.info(f"Parsing WhatWeb results for session: {session_id}")
        _excluded = ["UncommonHeaders", "Open-Graph-Protocol", "Title", "Frame", "Script", "HTML5"]
        _trivial = ["Email", "Script", "IP", "Country", "HTTPServer"]
        _tech: list[TechEntry] = []
        _cookies = []
        _extra = []
        with open(f"{self._base_report_path}/{session_id}.json", "r+") as f:
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
        self._cleanup(session_id)
        return {
            "technologies": [entry.model_dump() for entry in _tech],
            "cookies": _cookies,
            "extra": _extra,
        }

    def _cleanup(self, session_id: str) -> None:
        import docker
        logger.info("Cleaning up WhatWeb artifacts")
        # Path(f"{self._base_report_path}/{session_id}.json").unlink(missing_ok=True)
        client = docker.from_env()
        try:
            container = client.containers.get(f"{self._prefix}_{session_id}")
            container.stop(timeout=5)
            container.remove()
        except docker.errors.NotFound:
            logger.warning(f"Could not find container with ID: {self._prefix}_{session_id}. Skipping cleanup")

    def _spawn(self, container_name: str, ctx: ScanContext) -> Container:
        import docker
        logger.info(f"Spawning container: {self._prefix}_{container_name}")
        client = docker.from_env()
        return client.containers.run(
            image="localhost/whatweb",
            name=f"{self._prefix}_{container_name}",
            command=[
                "./whatweb",
                "-a", "3",
                "--log-json", f"/reports/{container_name}.json",
                ctx.primary_url
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

    def _spawn_headless(self, container_name: str, ctx: ScanContext) -> Container:
        pass

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