import json
from pathlib import Path

from docker.models.containers import Container
from loguru import logger

from app.modules.pipeline.context import DiscoveryContext
from app.modules.interfaces.base import IScanner
from app.modules.interfaces.options import BaseContext, HttpxContext
from app.modules.pipeline.context import TechEntry


class HttpxScanner(IScanner):
    #TODO: httpx can run multiple requests on several endpoints at the same time
    # Might be better to first launch subfinder then pipe its results to scanners.
    _base_report_path: str = f"{Path.cwd()}/app/reports/httpx"
    _prefix: str = "httpx"
    _scanner_context: BaseContext = HttpxContext() # might bite me in the ass later for hogging so much memory for building objects lol

    def start_scan(self, session_id: str, ctx: DiscoveryContext) -> dict:
        logger.info(f"Starting HTTPX scan: {session_id}")
        self._scanner_context.session_id = session_id
        container = self._spawn(session_id, ctx)

        result = container.wait()
        exit_code = result["StatusCode"]
        if exit_code != 0:
            # throw logs and errors
            logger.debug(f"HTTPX exited abruptly! Exit code: {exit_code}")
            container.remove()
            raise RuntimeError(f"HTTPX failed with exit code {exit_code}")
        container.remove()
        return self.parse_results(session_id)

    def parse_results(self, session_id: str) -> BaseContext:
        # TODO: The scanner involves some custom keys for different CMS', explore and add them later
        # Important keys: tls, tech, cpe
        logger.info(f"Parsing HTTPX results for session: {session_id}")
        versioned_tech: list[TechEntry] = []
        non_versioned_tech: list[TechEntry] = []
        with open(f"{self._base_report_path}/{session_id}.json") as f:
            for line in f.read().splitlines():
                json_line: dict = json.loads(line) # I do not know yet if this will change into an array if multiple urls are fed
                if not json_line:
                    continue # may be a break or return when empty. Need to test

                for tech in json_line.get("tech"):
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
        self._scanner_context.content = {
            "technologies": {
                "versioned": versioned_tech,
                "non_versioned": non_versioned_tech
            },
            "cpe": json_line.get("cpe"),
            "tls": json_line.get("tls"),
        }
        self._cleanup(session_id)
        return self._scanner_context

    def _cleanup(self, session_id: str) -> None:
        import docker
        logger.info("Cleaning up HTTPX artifacts")
        Path(f"{self._base_report_path}/{session_id}.json").unlink(missing_ok=True)
        client = docker.from_env()
        try:
            container = client.containers.get(session_id)
            container.stop(timeout=5)
            container.remove()
        except docker.errors.NotFound:
            logger.warning(f"Could not find container with ID: {self._prefix}_{session_id}. Skipping cleanup")
            pass

    def _spawn(self, container_name: str, ctx: DiscoveryContext) -> Container:
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