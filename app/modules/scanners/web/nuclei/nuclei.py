import time
from pathlib import Path

from docker.models.containers import Container
from loguru import logger

from modules.interfaces.scanners import IContainerScanner
from app.modules.interfaces.types.options import ScannerTaskResult
from app.modules.interfaces.types.context import ScanContext
from app.modules.scanners.web.nuclei.nuclei_context import NucleiContext, NucleiRecord, NucleiInfo
from app.modules.utils.utils import text_io_to_dict_list
from app.modules.scanners.web.nuclei.nuclei_context import NucleiClassification


class Nuclei(IContainerScanner):
    report_path = f"{Path.cwd()}/app/reports/nuclei"
    scanner_name = "nuclei"
    scanner_type = "container"
    _scanner_context: NucleiContext
    _timeout = 18_000

    def __init__(self):
        self._scanner_context = NucleiContext()

    def start_scan(self, session_id: str, ctx: ScanContext) -> dict:
        logger.info(f"Starting Nuclei scan: {session_id}")
        started = time.monotonic()

        try:
            container = self.spawn_container(session_id, ctx)
            container_result = container.wait(timeout=self._timeout)
            exit_code = container_result.get("StatusCode")
            assert isinstance(container, Container)
            logs = container.logs(stdout=True, stderr=True).decode(errors="replace")
            if exit_code != 0:
                logger.error(f"Nuclei has exited abruptly on exit code: {exit_code}")
                return ScannerTaskResult(
                    scanner="nuclei",
                    phase="attack",
                    status="failed",
                    result=None,
                    error=f"Nuclei exited with code {exit_code}",
                    stdout=logs,
                    stderr=None,
                    exit_code=exit_code,
                    runtime_ms=(time.monotonic() - started) * 1_000,
                ).model_dump()

            parsed = self.parse_results(session_id)
            return ScannerTaskResult(
                scanner="nuclei",
                phase="attack",
                status="success",
                result=parsed,
                stdout=logs,
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
                scanner="nuclei",
                phase="attack",
                status=status,
                result=None,
                error=str(e),
                runtime_ms=(time.monotonic() - started) * 1_000,
            ).model_dump()
        finally:
            self.cleanup(session_id)

    def parse_results(self, session_id: str) -> dict | None:
        _json_items: list[dict]
        _returnable: list[NucleiRecord] = []
        with open(f"{self.report_path}/{session_id}.json", "r") as f:
            _json_items = text_io_to_dict_list(f, False)
            for record in _json_items:
                classification = None
                _cve_id = None
                _cwe_id = None
                if record["info"].get("classification", None):
                    classification = NucleiClassification(
                        cve_id = record["info"]["classification"]["cve-id"],
                        cwe_id = record["info"]["classification"]["cwe-id"]
                    )
                info = NucleiInfo(
                    name = record["info"]["name"],
                    tags = record["info"]["tags"],
                    description = record["info"].get("description", None),
                    severity= record["info"]["severity"],
                    reference= record["info"].get("reference", None),
                    classification=classification
                )
                _returnable.append(NucleiRecord(
                    data=None,
                    template=record["template"],
                    template_id=record["template-id"],
                    url=record.get("url", ""),
                    info=info,
                    matched_at=record["matched-at"],
                    request=record.get("request", None),
                    curl_command=record.get("curl-command", None)
                ))
            return self._parse_to_sarif(_returnable)

    def cleanup(self, session_id: str) -> None:
        from docker import errors as docker_errors, from_env as docker_env
        logger.info("Cleaning up Nuclei artifacts")
        # Path(f"{self.report_path}/{session_id}.json").unlink(missing_ok=True)
        # Path(f"{self.report_path}/headless_{session_id}.json").unlink(missing_ok=True)
        client = docker_env()
        try:
            container = client.containers.get(f"{self.scanner_name}_{session_id}")
            container.stop(timeout=5)
            container.remove()
            # headless_container = client.containers.get(f"{self.scanner_name}_headless_{session_id}")
            # headless_container.stop(timeout=5)
            # headless_container.remove()
        except docker_errors.NotFound:
            logger.warning("Containers could not be found! Skipping cleanup...")
            return

    def spawn_container(self, session_id: str, ctx: ScanContext) -> Container:
        import docker
        logger.info(f"Spawning container: {self.scanner_name}_{session_id}")
        client = docker.from_env()
        return client.containers.run(
            image="projectdiscovery/nuclei",
            name=f"{self.scanner_name}_{session_id}",
            command=[
                "-u", ctx.primary_url,
                "-v",
                "-j",
                "-o", f"/reports/{session_id}.json",
                "-etags", "wp-plugin" # TODO: remove @ prod
                "-fhr",
                # "-dast", # Dast should be a separate task in celery
                "-duc" # Templates are updated before the server starts
            ],
            volumes={
                self.report_path: {
                    "bind": "/reports/",
                    "mode": "rw",
                },
                f"{Path.cwd()}/app/templates/nuclei/": {
                    "bind": "/root/nuclei-templates",
                    "mode": "ro"
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
            image="projectdiscovery/nuclei",
            name=f"{self.scanner_name}_headless_{session_id}",
            command=[],
            volumes={
                self.report_path: {
                    "bind": "/reports/",
                    "mode": "rw",
                }
            },
            detach=True,
            auto_remove=False,
        )

    @staticmethod
    def _parse_to_sarif(results: list[NucleiRecord]) -> dict | None:
        if results is None:
            return None
        nuclei_results = results
        _sarif_rules: list = []
        _sarif_results: list = []
        for result in nuclei_results:
            _sarif_rules.append({
                "id": result.template_id,
                "name": result.template,
                "fullDescription": {"text": result.info.description},
                "help": {
                    "text": result.info.reference
                },
                "properties": {
                    "curlCommand": result.curl_command,
                    "request": result.request,
                    "tags": result.info.tags,
                    "classification": result.info.classification
                },
                "level": result.info.severity
            })
            _sarif_results.append({
                "ruleId": result.template_id,
                "message": {"text": result.info.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": result.matched_at}
                        }
                    }
                ],
                "properties": {
                    "severity": result.info.severity,
                }
            })

        _sarif_report = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Nuclei",
                            "rules": _sarif_rules
                        }
                    },
                    "results": _sarif_results
                }
            ]
        }
        return _sarif_report