import json
from pathlib import Path

from docker.models.containers import Container

from app.modules.pipeline.context import DiscoveryContext
from app.modules.scanners.base import IScanner


class Subfinder(IScanner):
    _BASE_REPORT_PATH: str = f"{Path.cwd()}/app/reports/subfinder"

    def start_scan(self, session_id: str, ctx: DiscoveryContext) -> dict:
        container = self._spawn(session_id, ctx)

        result = container.wait()
        exit_code = result["StatusCode"]

        if exit_code != 0:
            #throw logs and errors
            container.remove()
            raise RuntimeError(f"Subfinder failed with exit code {exit_code}")
        container.remove()
        return self.parse_results(session_id)

    def parse_results(self, session_id: str) -> dict:
        # do some parsing here and return a dict
        with open(f"{self._BASE_REPORT_PATH}/{session_id}.json") as f:
            base_input = json.loads(f.readline()).get("input")
            sources: set = set()
            hosts: list = []
            for line in f.read().splitlines():
                json_line: dict = json.loads(line)
                for source in json_line.get("sources"):
                    sources.add(source)
                hosts.append(json_line.get("host"))
            collectable: dict = {base_input: {"hosts": hosts, "sources": sources}}
        self._cleanup(session_id)
        return collectable

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
        return client.containers.run(
            image="projectdiscovery/subfinder",
            name=container_name,
            command=f"-d {ctx.primary_url} -all -cs -oJ -o /reports/{container_name}.json",
            volumes={
                self._BASE_REPORT_PATH: {
                    "bind": "/reports/",
                    "mode": "rw",
                }
            },
            detach=True,
            auto_remove=False,
        )