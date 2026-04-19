import json
from pathlib import Path

from docker.models.containers import Container
from loguru import logger

from app.modules.interfaces.options import HttpxContext
from app.modules.pipeline.context import TechEntry, ScanContext
from app.modules.tasks.discovery.contexts.preamble_context import PreambleContext
from app.modules.interfaces.base import IPhaseContainerScanner


class HttpxScanner(IPhaseContainerScanner):
    #TODO: httpx can run multiple requests on several endpoints at the same time
    # Might be better to first launch subfinder then pipe its results to scanners.
    _base_report_path: str = f"{Path.cwd()}/app/reports/httpx"
    _prefix: str = "httpx"
    _scanner_context: HttpxContext

    def __init__(self):
        self._scanner_context = HttpxContext()

    def start_scan(self, session_id: str, ctx: ScanContext, phase_ctx: PreambleContext) -> dict:
        logger.info(f"Starting HTTPX scan: {session_id}")
        self._scanner_context.session_id = session_id

        container = self._spawn(session_id, ctx)
        result = container.wait()
        if result.get('StatusCode') != 0:
            # throw logs and errors
            logger.error(f"HTTPX has exited abruptly on exit code: {result.get('StatusCode')}")
            container.remove()
            raise
        return self._parse_results(session_id)

    def _parse_results(self, session_id: str) -> dict:
        # TODO: The scanner involves some custom keys for different CMS', explore and add them later
        # Important keys: tls, tech, cpe
        logger.info(f"Parsing HTTPX results for session: {session_id}")
        versioned_tech: list[TechEntry] = []
        non_versioned_tech: list[TechEntry] = []
        with open(f"{self._base_report_path}/{session_id}.json") as f:
            for line in f.read().splitlines():
                json_line: dict = json.loads(line) # I do not know yet if this will change into an array if multiple urls are fed
                if json_line.get("failed"):
                    return None
                technologies = json_line.get("tech")
                if not json_line:
                    continue # may be a break or return when empty. Need to test
                assert isinstance(technologies, list)
                for tech in technologies:
                    # each entry is a string with a structure of name:version
                    arr = tech.split(":") if tech.__contains__(":") else [tech]
                    if len(arr) == 1:
                        non_versioned_tech.append(TechEntry(
                            name=arr[0],
                            version="",
                            source="httpx"
                        ))
                        continue
                    versioned_tech.append(TechEntry(
                        name=arr[0],
                        version=arr[1],
                        source="httpx"
                    ))

        # after everything is done, store it on content
        content = {
            "technologies": {
                "versioned": [t.__dict__ for t in versioned_tech],
                "non_versioned": [t.__dict__ for t in non_versioned_tech]
            },
            "cpe": json_line.get("cpe"),
            "tls": json_line.get("tls"),
        }
        self._scanner_context.content = content
        self._cleanup(session_id)
        return content

    def _cleanup(self, session_id: str) -> None:
        import docker
        logger.info("Cleaning up HTTPX artifacts")
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
            image="projectdiscovery/httpx",
            name=f"{self._prefix}_{container_name}",
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
                "-o", f"/reports/{container_name}.json",
                "-u", ctx.primary_url
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