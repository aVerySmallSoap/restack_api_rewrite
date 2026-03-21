import json
from pathlib import Path
import hashlib

from docker.models.containers import Container
from loguru import logger

from app.modules.pipeline.context import DiscoveryContext
from app.modules.interfaces.base import IScanner
from app.modules.utils.utils import map_endpoints
from app.modules.interfaces.enums.options import KatanaContext
from app.modules.utils.utils import is_same_host


class Katana(IScanner):
    _BASE_REPORT_PATH: str = f"{Path.cwd()}/app/reports/katana"

    def start_scan(self, session_id: str, ctx: DiscoveryContext, opts: KatanaContext = KatanaContext()) -> dict:
        logger.info(f"Starting Katana scan: {session_id}")
        # prepare headless just in case
        headless_container: Container | None = None
        opts.primary_host = ctx.primary_host

        if opts.is_two_pass:
            logger.info("Scan is configured to be a two-pass scan. Spawning a headless container")
            headless_container = self._spawn_headless(session_id, ctx)
            opts.headless_container_name = headless_container.name

        container = self._spawn(session_id, ctx)
        opts.standard_container_name = container.name
        result = container.wait()
        headless_result = headless_container.wait() if headless_container else None
        katana_metadata: dict = {
            "standard": {
                "container": container,
                "exit_code": result["StatusCode"]
            },
            "headless": {
                "container": headless_container,
                "exit_code": headless_result["StatusCode"]
            } if headless_container else None,
        }

        for meta_container in katana_metadata.values():
            if not meta_container:
                continue
            if meta_container.get("exit_code") != 0:
                logger.error(f"Katana container: {meta_container.get('container').name} has exited abruptly! Error code: {meta_container.get("exit_code")}")
                raise RuntimeError(f"Katana container: {meta_container.get('container').name} exited abruptly!")
        return self.parse_results(session_id, opts)

    def parse_results(self, session_id: str, opts: KatanaContext = KatanaContext()) -> dict:
        from urllib.parse import urlparse
        logger.info(f"Parsing Katana results for session: {session_id}")
        collection: list[dict] = []
        hash_map: list[str] = []
        endpoints: set = set()

        # endpoint validation
        # check for a headless_ report to signal a two-pass
        if opts.is_two_pass:
            with open(f"{self._BASE_REPORT_PATH}/headless_{session_id}.json") as f:
                for line in f.read().splitlines():
                    json_line = json.loads(line)
                    if not is_same_host(opts.primary_host, json_line["request"].get("endpoint")):
                        print(f"We hit something! Check if they are the same: {opts.primary_host} ? {json_line["request"].get("endpoint")}")
                        continue
                    line_hash = hashlib.sha256(line.encode('utf-8')).hexdigest()
                    hash_map.append(line_hash)
                    endpoints.add(json_line["request"].get("endpoint"))
                    collection.append(json_line)

        with open(f"{self._BASE_REPORT_PATH}/standard_{session_id}.json") as f:
            for line in f.read().splitlines():
                json_line = json.loads(line)
                if not is_same_host(opts.primary_host, json_line["request"].get("endpoint")):
                    continue
                line_hash = hashlib.sha256(line.encode('utf-8')).hexdigest()
                if line_hash in hash_map:
                    continue
                endpoints.add(json_line["request"].get("endpoint"))
                collection.append(json_line)
        site_map = map_endpoints(endpoints)
        # test output
        with open(f"{self._BASE_REPORT_PATH}/parsed_{session_id}.json", "w") as writable:
            writable.write(json.dumps({"collection": collection, "site_map": site_map}, indent=4))

        self._cleanup(session_id, opts)
        return {"collection": collection, "site_map": site_map}

    def _cleanup(self, session_id: str, opts: KatanaContext = KatanaContext()) -> None:
        import docker
        logger.info("Cleaning up Katana artifacts")

        if opts.is_two_pass:
            Path(f"{self._BASE_REPORT_PATH}/headless_{session_id}.json").unlink(missing_ok=True)

        Path(f"{self._BASE_REPORT_PATH}/standard_{session_id}.json").unlink(missing_ok=True)
        client = docker.from_env()
        try:
            container = client.containers.get(opts.standard_container_name)
            container.stop(timeout=5)
            container.remove()
            if opts.is_two_pass:
                headless_container = client.containers.get(opts.headless_container_name)
                headless_container.stop(timeout=5)
                headless_container.remove()
        except docker.errors.NotFound:
            logger.warning(f"Containers could not be found! Skipping cleanup...")
            return

    def _spawn(self, container_name: str, ctx: DiscoveryContext) -> Container:
        import docker
        logger.info(f"Spawning container: katana_{container_name}")
        client = docker.from_env()
        return client.containers.run(
            image="projectdiscovery/katana",
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

    def _spawn_headless(self, container_name: str, ctx: DiscoveryContext, opts: KatanaContext = KatanaContext()) -> Container:
        import docker
        logger.info(f"Spawning headless container: katana_headless_{container_name}")
        client = docker.from_env()
        return client.containers.run(
            image="projectdiscovery/katana",
            name=f"katana_headless_{container_name}",
            command=[
                "-headless",
                "-scp", opts.headless_chrome_binary,
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