from datetime import datetime, timezone
from pathlib import Path

from docker.models.containers import Container
from loguru import logger
from sslyze import ServerScanRequest, ServerNetworkLocation, ScanCommand, Scanner, SslyzeOutputAsJson, \
    ServerScanResultAsJson

from app.modules.pipeline.context import DiscoveryContext
from app.modules.scanners.base import IScanner


class SSLyze(IScanner):
    _BASE_REPORT_PATH: str = f"{Path.cwd()}/app/reports/sslyze"
    _BASELINE_COMMANDS = {
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
        ScanCommand.ELLIPTIC_CURVES,
        ScanCommand.TLS_COMPRESSION,
        ScanCommand.TLS_1_3_EARLY_DATA,
        ScanCommand.OPENSSL_CCS_INJECTION,
        ScanCommand.TLS_FALLBACK_SCSV,
        ScanCommand.HEARTBLEED,
        ScanCommand.ROBOT,
        ScanCommand.SESSION_RENEGOTIATION,
        ScanCommand.SESSION_RESUMPTION,
        ScanCommand.HTTP_HEADERS,
        ScanCommand.TLS_EXTENDED_MASTER_SECRET,
    }

    def start_scan(self, session_id: str, ctx: DiscoveryContext) -> dict:
        logger.info(f"Starting SSlyze scan: {session_id}")
        requests = [ServerScanRequest(
            server_location=ServerNetworkLocation(ctx.primary_url.removeprefix("https://"), 443),
            scan_commands=self._BASELINE_COMMANDS
        )]

        scanner = Scanner()
        date_scans_started = datetime.now(timezone.utc)

        # In SSLyze 6.x, queue_scans() takes a list of requests
        scanner.queue_scans(requests)

        results = list(scanner.get_results())

        date_scans_completed = datetime.now(timezone.utc)

        json_output = SslyzeOutputAsJson(
            server_scan_results=[
                ServerScanResultAsJson.model_validate(result)
                for result in results
            ],
            invalid_server_strings=[],
            date_scans_started=date_scans_started,
            date_scans_completed=date_scans_completed,
        )

        json_str = json_output.model_dump_json(indent=2)
        Path(f"{self._BASE_REPORT_PATH}/{session_id}.json").write_text(json_str)
        return {}  # list of TLSFinding

    def parse_results(self, session_id: str) -> dict:
        pass

    def _cleanup(self, session_id: str) -> None:
        pass

    def _spawn(self, container_name: str, ctx: DiscoveryContext) -> Container:
        pass