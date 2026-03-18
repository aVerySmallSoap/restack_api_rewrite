from pathlib import Path

from docker.models.containers import Container

from app.modules.pipeline.context import DiscoveryContext
from app.modules.scanners.base import IScanner


class WappalyzerNext(IScanner):
    _BASE_REPORT_PATH: str = f"{Path.cwd()}/app/reports/wappalyzer_next"

    def start_scan(self, session_id: str, ctx: DiscoveryContext) -> dict:
        container = self._spawn(session_id, ctx)

        result = container.wait()
        exit_code = result["StatusCode"]

        if exit_code != 0:
            # throw logs and errors
            # container.remove()
            raise RuntimeError(f"WappalyzerNext failed with exit code {exit_code}")
        # container.remove()
        return self.parse_results(session_id)

    def parse_results(self, session_id: str) -> dict:
        with open(f"{self._BASE_REPORT_PATH}/{session_id}.json") as f:
            for line in f.read().splitlines():
                print(line)
        # self._cleanup(session_id)
        pass

    def _cleanup(self, session_id: str) -> None:
        import docker
        Path(f"{self._BASE_REPORT_PATH}/{session_id}.json").unlink(missing_ok=True)
        client = docker.from_env()
        try:
            container = client.containers.get(session_id)
            container.stop(timeout=5)
            container.remove()
        except docker.errors.NotFound:
            pass

    def _spawn(self, container_name: str, ctx: DiscoveryContext) -> Container:
        import docker
        client = docker.from_env()
        client.containers.run(
            image="localhost/wappalyzer",  # TODO: publish this image to docker.io
            name=container_name,
            command=f"--scan-type balanced -oJ /reports/{container_name}.json -i {ctx.primary_url}",
            volumes={
                self._BASE_REPORT_PATH: {
                    "bind": "/reports/",
                    "mode": "rw",
                }
            },
            detach=True,
        )
        return client.containers.get(container_name)