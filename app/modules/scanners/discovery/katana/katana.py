import json
from pathlib import Path
import hashlib

from docker.models.containers import Container
from loguru import logger

from app.modules.pipeline.context import DiscoveryContext
from app.modules.scanners.base import IScanner
from modules.utils.utils import map_endpoints


class Katana(IScanner):
    _BASE_REPORT_PATH: str = f"{Path.cwd()}/app/reports/katana"


    def start_scan(self, session_id: str, ctx: DiscoveryContext) -> dict:
        logger.info(f"Starting Katana scan: {session_id}")
        if ctx.kata_two_pass:
            logger.info("Started a two-pass scan")
            container = self._spawn(session_id, ctx)
            headless_container = self._spawn_headless(session_id, ctx)

            result = container.wait()
            headless_result = headless_container.wait()
            exit_code, headless_exit_code = result["StatusCode"], headless_result["StatusCode"]

            if exit_code != 0:
                logger.debug(f"Katana exited abruptly! Exit code: {exit_code}")
                # container.remove()
                raise RuntimeError(f"Katana failed with exit code {exit_code}")
            if headless_exit_code != 0:
                logger.debug(f"Headless Katana exited abruptly! Exit code: {exit_code}")
                # headless_container.remove()
                raise RuntimeError(f"Headless Katana failed with exit code {exit_code}")
            # remove containers
            # container.remove()
            # headless_container.remove()
            return self.parse_results(session_id)
        else:
            container = self._spawn(session_id, ctx)
            result = container.wait()
            exit_code = result["StatusCode"]

            if exit_code != 0:
                logger.debug(f"Katana exited abruptly! Exit code: {exit_code}")
                # container.remove()
                raise RuntimeError(f"Katana failed with exit code {exit_code}")
            # container.remove()
            return self.parse_results(session_id)

    def parse_results(self, session_id: str) -> dict:
        logger.info(f"Parsing Katana results for session: {session_id}")
        collection: list[dict] = []
        hash_map: list[str] = []
        endpoints: set = set()

        # endpoint validation
        # check for a headless_ report to signal a two-pass
        if Path.exists(Path(f"{self._BASE_REPORT_PATH}/headless_{session_id}.json")):
            with open(f"{self._BASE_REPORT_PATH}/headless_{session_id}.json") as f:
                for line in f.read().splitlines():
                    line_hash = hashlib.sha256(line.encode('utf-8')).hexdigest()
                    hash_map.append(line_hash)
                    json_line = json.loads(line)
                    endpoints.add(json_line.get("endpoint"))
                    collection.append(json_line)

        with open(f"{self._BASE_REPORT_PATH}/standard_{session_id}.json") as f:
            for line in f.read().splitlines():
                line_hash = hashlib.sha256(line.encode('utf-8')).hexdigest()
                if line_hash in hash_map:
                    continue
                json_line = json.loads(line)
                endpoints.add(json_line.get("endpoint"))
                collection.append(json_line)
        site_map = map_endpoints(endpoints)
        return {"collection": collection, "site_map": site_map}

    def _cleanup(self, session_id: str) -> None:
        import docker
        logger.info("Cleaning up Katana artifacts")

        Path(f"{self._BASE_REPORT_PATH}/standard_{session_id}.json").unlink(missing_ok=True)
        Path(f"{self._BASE_REPORT_PATH}/headless_{session_id}.json").unlink(missing_ok=True)
        client = docker.from_env()
        try:
            container = client.containers.get(f"katana_{session_id}")
            headless_container = client.containers.get(f"headless_katana_{session_id}")
            container.stop(timeout=5)
            headless_container.stop(timeout=5)
            container.remove()
            headless_container.remove()
        except docker.errors.NotFound:
            logger.warning(f"Could not find container with name: katana_{session_id}. Skipping cleanup")
            pass

    def _spawn(self, container_name: str, ctx: DiscoveryContext) -> Container:
        import docker
        logger.info(f"Spawning container: standard_{container_name}")
        client = docker.from_env()
        client.containers.run(
            image="projectdiscovery/katana",  # TODO: publish this image to docker.io
            name=f"katana_{container_name}",
            command=[
                "-or",
                "-ob",
                "-xhr",
                "-jc",
                "-kf", "all",
                "-rlm", "10",
                "-j",
                "-o", f"/reports/standard_{container_name}.json",
                "-u", ctx.primary_url,
                "-silent",
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
        return client.containers.get(f"katana_{container_name}")

    def _spawn_headless(self, container_name: str, ctx: DiscoveryContext) -> Container:
        import docker
        logger.info(f"Spawning headless container: headless_{container_name}")
        client = docker.from_env()
        client.containers.run(
            image="projectdiscovery/katana",  # TODO: publish this image to docker.io
            name=f"headless_katana_{container_name}",
            command=[
                "-headless",
                "-scp", "/usr/bin/chromium",
                "-nos",
                "-or",
                "-ob",
                "-xhr",
                "-jc",
                "-kf", "all",
                "-rlm", "10",
                "-j",
                "-o", f"/reports/headless_{container_name}.json",
                "-u", ctx.primary_url,
                "-silent",
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
        return client.containers.get(f"headless_katana{container_name}")