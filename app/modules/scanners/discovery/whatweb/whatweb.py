from pathlib import Path

from docker.models.containers import Container
from loguru import logger

from app.modules.pipeline.context import DiscoveryContext
from app.modules.interfaces.base import IScanner


class WhatWeb(IScanner):
    _BASE_REPORT_PATH: str = f"{Path.cwd()}/app/reports/whatweb"

    def start_scan(self, session_id: str, ctx: DiscoveryContext) -> dict:
        logger.info(f"Starting WhatWeb scan: {session_id}")
        container = self._spawn(session_id, ctx)

        result = container.wait()
        exit_code = result["StatusCode"]

        if exit_code != 0:
            logger.debug(f"WhatWeb exited abruptly! Exit code: {exit_code}")
            container.remove()
            raise RuntimeError(f"WhatWeb failed with exit code {exit_code}")
        container.remove()
        return self.parse_results(session_id)

    def parse_results(self, session_id: str) -> dict:
        logger.info(f"Parsing WhatWeb results for session: {session_id}")
        with open(f"{self._BASE_REPORT_PATH}/{session_id}.json") as f:
            for line in f.read().splitlines():
                print(line)
        # self._cleanup(session_id)
        pass

    def _cleanup(self, session_id: str) -> None:
        import docker
        logger.info("Cleaning up WhatWeb artifacts")
        Path(f"{self._BASE_REPORT_PATH}/{session_id}.json").unlink(missing_ok=True)
        client = docker.from_env()
        try:
            container = client.containers.get(session_id)
            container.stop(timeout=5)
            container.remove()
        except docker.errors.NotFound:
            logger.warning(f"Could not find container with ID: whatweb_{session_id}. Skipping cleanup")
            pass

    def _spawn(self, container_name: str, ctx: DiscoveryContext) -> Container:
        import docker
        logger.info(f"Spawning container: whatweb_{container_name}")
        client = docker.from_env()
        return client.containers.run(
            image="localhost/whatweb",
            name=f"whatweb_{container_name}",
            command=[
                "./whatweb",
                "-a", "3",
                "--log-json", f"/reports/{container_name}.json",
                ctx.primary_url
            ],
            volumes={
                self._BASE_REPORT_PATH: {
                    "bind": "/reports/",
                    "mode": "rw",
                }
            },
            detach=True,
            auto_remove=False,
        )