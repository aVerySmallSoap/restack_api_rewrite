import time
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger
from sslyze import ServerScanRequest, ServerNetworkLocation, ScanCommand, Scanner, SslyzeOutputAsJson, \
    ServerScanResultAsJson

from modules.interfaces.types.context import ScanContext
from app.modules.interfaces.enums.scanners import IBaseScanner
from app.modules.interfaces.types.options import ScannerTaskResult


class SSLyze(IBaseScanner):
    _base_report_path: str = f"{Path.cwd()}/app/reports/sslyze"
    _prefix = "sslyze"
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

    def start_scan(self, session_id: str, ctx: ScanContext) -> ScannerTaskResult:
        logger.info(f"Starting SSLyze scan: {session_id}")
        started = time.monotonic()

        if ctx.primary_url.__contains__("https://"):
            requests = [ServerScanRequest(
                server_location=ServerNetworkLocation(ctx.primary_host, 443),
                scan_commands=self._BASELINE_COMMANDS
            )]
        else:
            requests = [ServerScanRequest(
                server_location=ServerNetworkLocation(ctx.primary_host, 80),
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

        Path(f"{self._base_report_path}/{session_id}.json").write_text(json_output.model_dump_json())
        return ScannerTaskResult(
            scanner="sslyze",
            phase="asset",
            status="success",
            result=json_output.model_dump(),
            stdout=None,
            exit_code=None,
            runtime_ms=int((time.monotonic() - started) * 1000),
        ).model_dump()

    def parse_results(self, session_id: str) -> dict:
        pass

    def cleanup(self, session_id: str) -> None:
        pass