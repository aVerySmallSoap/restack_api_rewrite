import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger
from sslyze import (
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommand,
    Scanner,
    SslyzeOutputAsJson,
    ServerScanResultAsJson,
)

from app.modules.interfaces.types.context import ScanContext
from app.modules.interfaces.scanners import IBaseScanner
from app.modules.interfaces.types.options import ScannerTaskResult


class SSLyze(IBaseScanner):
    report_path = f"{Path.cwd()}/app/reports/sslyze"
    scanner_name = "sslyze"
    scanner_type = "cmd"

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

    WEAK_PROTOCOLS = {
        "ssl_2_0_cipher_suites": ("SSL_2_0", "CRITICAL"),
        "ssl_3_0_cipher_suites": ("SSL_3_0", "CRITICAL"),
        "tls_1_0_cipher_suites": ("TLS_1_0", "HIGH"),
        "tls_1_1_cipher_suites": ("TLS_1_1", "HIGH"),
    }

    CIPHER_SUITE_KEYS = [
        "ssl_2_0_cipher_suites",
        "ssl_3_0_cipher_suites",
        "tls_1_0_cipher_suites",
        "tls_1_1_cipher_suites",
        "tls_1_2_cipher_suites",
        "tls_1_3_cipher_suites",
    ]

    def start_scan(self, session_id: str, ctx: ScanContext) -> ScannerTaskResult:
        logger.info(f"Starting SSLyze scan: {session_id}")
        started = time.monotonic()

        if ctx.primary_url.startswith("https://"):
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

        json_str = json_output.model_dump_json()
        Path(self.report_path).mkdir(parents=True, exist_ok=True)
        Path(f"{self.report_path}/{session_id}.json").write_text(json_str)

        return ScannerTaskResult(
            scanner="sslyze",
            phase="asset",
            status="success",
            result=self.parse_results(session_id),
            stdout=None,
            exit_code=None,
            runtime_ms=int((time.monotonic() - started) * 1000),
        ).model_dump()

    def parse_results(self, session_id: str) -> dict | None:
        with open(f"{self.report_path}/{session_id}.json") as f:
            json_load = json.load(f)
            scan_results = json_load.get("server_scan_results") or []

            if not scan_results:
                return None

            # Assumption: one SSLyze result per scan because your app scans one base URL.
            server = scan_results[0]

            if server.get("connectivity_status") != "COMPLETED":
                return {
                    "status": "ERROR",
                    "reason": "Connectivity did not complete",
                    "evidence": {
                        "connectivity_status": server.get("connectivity_status"),
                        "connectivity_error_trace": server.get("connectivity_error_trace"),
                    },
                }

            scan_result = server.get("scan_result")
            if scan_result is None:
                return {
                    "status": "ERROR",
                    "reason": "No scan_result returned",
                    "evidence": {},
                }

            certificates, certificate_findings = self._parse_certificates(scan_result)
            supported_suites, cipher_findings = self._parse_cipher_suites(scan_result)
            direct_findings = self._parse_direct_vulnerability_checks(scan_result)

            all_findings = [
                *certificate_findings,
                *cipher_findings,
                *direct_findings,
            ]

            severity_rank = {
                "CRITICAL": 5,
                "HIGH": 4,
                "MEDIUM": 3,
                "LOW": 2,
                "INFO": 1,
            }

            highest_severity = "INFO"
            if all_findings:
                highest_severity = max(
                    all_findings,
                    key=lambda item: severity_rank.get(item["severity"], 0),
                )["severity"]

            return {
                "status": "COMPLETED",
                "target": {
                    "hostname": server.get("server_location", {}).get("hostname"),
                    "port": server.get("server_location", {}).get("port"),
                    "ip_address": server.get("server_location", {}).get("ip_address"),
                },
                "summary": {
                    "highest_severity": highest_severity,
                    "certificate_count": len(certificates),
                    "supported_cipher_count": len(supported_suites),
                    "finding_count": len(all_findings),
                },
                "certificates": certificates,
                "supported_suites": supported_suites,
                "findings": all_findings,
            }


    def cleanup(self, session_id: str) -> None:
        pass


    #noinspection D
    def _parse_certificates(
        self,
        scan_results: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        certificates = []
        findings = []

        certificate_results = self._scan_attempt_result(scan_results, "certificate_info")
        if certificate_results is None:
            self._add_finding(
                findings,
                "INFO",
                "Certificate information unavailable",
                "SSLyze did not return a completed certificate_info result.",
            )
            return certificates, findings

        now = datetime.now(timezone.utc)

        for deployment_index, deployment in enumerate(
            certificate_results.get("certificate_deployments", [])
        ):
            chain = deployment.get("received_certificate_chain") or []

            if not chain:
                self._add_finding(
                    findings,
                    "HIGH",
                    "No certificate chain received",
                    "The server did not return a certificate chain for this deployment.",
                    {"deployment_index": deployment_index},
                )
                continue

            leaf = chain[0]

            expires_at = self._parse_dt(leaf["not_valid_after"])
            days_left = (expires_at - now).days
            expiry = self._expiry_severity(days_left)

            public_key = leaf.get("public_key") or {}
            san = leaf.get("subject_alternative_name") or {}
            ocsp_response = deployment.get("ocsp_response") or {}

            cert_data = {
                "deployment_index": deployment_index,
                "subject": leaf.get("subject", {}).get("rfc4514_string"),
                "issuer": leaf.get("issuer", {}).get("rfc4514_string"),
                "serial_number": leaf.get("serial_number"),
                "fingerprint_sha256": leaf.get("fingerprint_sha256"),
                "public_key": public_key.get("algorithm"),
                "key_size": public_key.get("key_size"),
                "ec_curve_name": public_key.get("ec_curve_name"),
                "signature_hash_algorithm": leaf.get("signature_hash_algorithm", {}).get("name"),
                "signature_algorithm": leaf.get("signature_algorithm_oid", {}).get("name"),
                "not_valid_before": leaf.get("not_valid_before"),
                "not_valid_after": leaf.get("not_valid_after"),
                "days_left": days_left,
                "expiry": expiry,
                "san_dns_names": san.get("dns_names", []),
                "san_ip_addresses": san.get("ip_addresses", []),
                "chain_length": len(chain),
                "chain_has_valid_order": deployment.get("received_chain_has_valid_order"),
                "chain_contains_anchor_certificate": deployment.get(
                    "received_chain_contains_anchor_certificate"
                ),
                "verified_chain_has_sha1_signature": deployment.get(
                    "verified_chain_has_sha1_signature"
                ),
                "verified_chain_has_legacy_symantec_anchor": deployment.get(
                    "verified_chain_has_legacy_symantec_anchor"
                ),
                "ocsp_status": ocsp_response.get("certificate_status"),
                "ocsp_response_status": ocsp_response.get("response_status"),
                "ocsp_trusted": deployment.get("ocsp_response_is_trusted"),
                "ocsp_this_update": ocsp_response.get("this_update"),
                "ocsp_next_update": ocsp_response.get("next_update"),
            }

            certificates.append(cert_data)

            if expiry != "INFO":
                self._add_finding(
                    findings,
                    expiry,
                    "Certificate is expired or near expiry",
                    f"Certificate expires in {days_left} day(s).",
                    cert_data,
                )

            if deployment.get("received_chain_has_valid_order") is False:
                self._add_finding(
                    findings,
                    "MEDIUM",
                    "Certificate chain has invalid order",
                    "The server returned the certificate chain in the wrong order.",
                    {"deployment_index": deployment_index},
                )

            if deployment.get("received_chain_contains_anchor_certificate") is True:
                self._add_finding(
                    findings,
                    "LOW",
                    "Server sends root certificate",
                    "The server includes the anchor/root certificate in the chain.",
                    {"deployment_index": deployment_index},
                )

            if deployment.get("verified_chain_has_sha1_signature") is True:
                self._add_finding(
                    findings,
                    "HIGH",
                    "Verified certificate chain uses SHA-1",
                    "At least one certificate in the verified chain uses a SHA-1 signature.",
                    {"deployment_index": deployment_index},
                )

            if deployment.get("verified_chain_has_legacy_symantec_anchor") is True:
                self._add_finding(
                    findings,
                    "HIGH",
                    "Verified chain uses legacy Symantec anchor",
                    "The certificate chain uses a legacy Symantec trust anchor.",
                    {"deployment_index": deployment_index},
                )

            if ocsp_response.get("certificate_status") == "REVOKED":
                self._add_finding(
                    findings,
                    "CRITICAL",
                    "Certificate is revoked",
                    "The OCSP response reports the certificate as revoked.",
                    ocsp_response,
                )

            if deployment.get("ocsp_response_is_trusted") is False:
                self._add_finding(
                    findings,
                    "MEDIUM",
                    "OCSP response is not trusted",
                    "SSLyze reported an untrusted OCSP response.",
                    ocsp_response,
                )

            failed_trust_stores = []
            for validation in deployment.get("path_validation_results", []):
                if validation.get("was_validation_successful") is False:
                    trust_store = validation.get("trust_store") or {}
                    failed_trust_stores.append({
                        "name": trust_store.get("name"),
                        "version": trust_store.get("version"),
                        "validation_error": validation.get("validation_error"),
                    })

            if failed_trust_stores:
                self._add_finding(
                    findings,
                    "HIGH",
                    "Certificate failed one or more trust-store validations",
                    "At least one trust store could not validate the certificate chain.",
                    {"failed_trust_stores": failed_trust_stores},
                )

        return certificates, findings

    #noinspection D
    def _parse_cipher_suites(
        self,
        scan_results: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        supported_suites = []
        findings = []

        for key in self.CIPHER_SUITE_KEYS:
            result = self._scan_attempt_result(scan_results, key)
            if result is None:
                continue

            accepted = result.get("accepted_cipher_suites") or []
            protocol_name = result.get("tls_version_used") or key.replace("_cipher_suites", "").upper()

            if accepted and key in self.WEAK_PROTOCOLS:
                deprecated_protocol, severity = self.WEAK_PROTOCOLS[key]

                self._add_finding(
                    findings,
                    severity,
                    f"Deprecated protocol supported: {deprecated_protocol}",
                    f"The server accepts at least one cipher suite over {deprecated_protocol}.",
                    {
                        "protocol": deprecated_protocol,
                        "accepted_cipher_count": len(accepted),
                    },
                )

            for accepted_cipher in accepted:
                cipher_suite = accepted_cipher.get("cipher_suite") or {}

                name = cipher_suite.get("name")
                key_size = cipher_suite.get("key_size", 0)

                # Important:
                # In SSLyze JSON, ephemeral_key is usually a sibling of cipher_suite,
                # not inside cipher_suite.
                ephemeral_key = accepted_cipher.get("ephemeral_key")

                if not name:
                    continue

                cipher_data = {
                    "protocol": protocol_name,
                    "name": name,
                    "openssl_name": cipher_suite.get("openssl_name"),
                    "key_size": key_size,
                    "is_anonymous": cipher_suite.get("is_anonymous"),
                    "has_ephemeral_key": ephemeral_key is not None,
                }

                supported_suites.append(cipher_data)

                for cipher_finding in self._classify_cipher(name, key_size, ephemeral_key):
                    self._add_finding(
                        findings,
                        cipher_finding["severity"],
                        cipher_finding["title"],
                        f"{name} is accepted under {protocol_name}.",
                        cipher_data,
                    )

        return supported_suites, findings

    #noinspection D
    def _parse_direct_vulnerability_checks(
        self,
        scan_results: dict[str, Any],
    ) -> list[dict[str, Any]]:
        findings = []

        # Heartbleed
        heartbleed = self._scan_attempt_result(scan_results, "heartbleed")
        if heartbleed and heartbleed.get("is_vulnerable_to_heartbleed") is True:
            self._add_finding(
                findings,
                "CRITICAL",
                "Heartbleed vulnerability detected",
                "The server is vulnerable to Heartbleed.",
                heartbleed,
            )

        # ROBOT
        robot = self._scan_attempt_result(scan_results, "robot")
        if robot:
            robot_result = robot.get("robot_result") or robot.get("result")

            if robot_result == "VULNERABLE_STRONG_ORACLE":
                self._add_finding(
                    findings,
                    "CRITICAL",
                    "ROBOT vulnerability detected",
                    "The server is vulnerable to ROBOT with a strong oracle.",
                    robot,
                )
            elif robot_result == "VULNERABLE_WEAK_ORACLE":
                self._add_finding(
                    findings,
                    "HIGH",
                    "ROBOT weak oracle detected",
                    "The server appears vulnerable to ROBOT, but exploitation may be less practical.",
                    robot,
                )
            elif robot_result == "UNKNOWN_INCONSISTENT_RESULTS":
                self._add_finding(
                    findings,
                    "MEDIUM",
                    "ROBOT result is inconclusive",
                    "SSLyze could not determine whether the server is vulnerable to ROBOT.",
                    robot,
                )

        # OpenSSL CCS Injection
        ccs = self._scan_attempt_result(scan_results, "openssl_ccs_injection")
        if ccs and ccs.get("is_vulnerable_to_ccs_injection") is True:
            self._add_finding(
                findings,
                "CRITICAL",
                "OpenSSL CCS injection vulnerability detected",
                "The server is vulnerable to OpenSSL CCS injection.",
                ccs,
            )

        # TLS compression / CRIME-style risk
        compression = self._scan_attempt_result(scan_results, "tls_compression")
        if compression and compression.get("supports_compression") is True:
            self._add_finding(
                findings,
                "HIGH",
                "TLS compression is enabled",
                "The server supports TLS compression, which can enable CRIME-style attacks.",
                compression,
            )

        # TLS 1.3 early data / replay risk
        early_data = self._scan_attempt_result(scan_results, "tls_1_3_early_data")
        if early_data and early_data.get("supports_early_data") is True:
            self._add_finding(
                findings,
                "MEDIUM",
                "TLS 1.3 early data is enabled",
                "The server accepts TLS 1.3 early data, which can introduce replay risk.",
                early_data,
            )

        # Session renegotiation
        renegotiation = self._scan_attempt_result(scan_results, "session_renegotiation")
        if renegotiation:
            if renegotiation.get("supports_secure_renegotiation") is False:
                self._add_finding(
                    findings,
                    "HIGH",
                    "Secure renegotiation is not supported",
                    "The server does not support secure TLS renegotiation.",
                    renegotiation,
                )

            if renegotiation.get("is_vulnerable_to_client_renegotiation_dos") is True:
                self._add_finding(
                    findings,
                    "HIGH",
                    "Client renegotiation DoS risk detected",
                    "The server appears vulnerable to client-initiated renegotiation denial-of-service.",
                    renegotiation,
                )

        # TLS fallback SCSV
        fallback = self._scan_attempt_result(scan_results, "tls_fallback_scsv")
        if fallback and fallback.get("supports_fallback_scsv") is False:
            self._add_finding(
                findings,
                "MEDIUM",
                "TLS_FALLBACK_SCSV not supported",
                "The server does not support TLS_FALLBACK_SCSV downgrade prevention.",
                fallback,
            )

        # HTTP headers / HSTS
        headers = self._scan_attempt_result(scan_results, "http_headers")
        if headers:
            if headers.get("http_error_trace"):
                self._add_finding(
                    findings,
                    "INFO",
                    "HTTP header check failed",
                    "SSLyze could not retrieve a valid HTTP response for header analysis.",
                    {"http_error_trace": headers.get("http_error_trace")},
                )
            elif headers.get("strict_transport_security_header") is None:
                self._add_finding(
                    findings,
                    "LOW",
                    "HSTS header missing",
                    "The server did not return a Strict-Transport-Security header.",
                    headers,
                )

        return findings

    def _classify_cipher(
        self,
        cipher_name: str,
        key_size: int,
        ephemeral_key: dict | None,
    ) -> list[dict[str, str]]:
        weak_cipher_tokens = [
            "NULL",
            "ANON",
            "EXPORT",
            "RC4",
            "3DES",
            "DES",
            "MD5",
            "SEED",
            "IDEA",
        ]

        findings = []
        upper = cipher_name.upper()

        if any(token in upper for token in weak_cipher_tokens):
            findings.append({
                "severity": "HIGH",
                "title": "Weak or deprecated cipher algorithm",
            })

        if key_size < 128:
            findings.append({
                "severity": "HIGH",
                "title": "Cipher key size below 128 bits",
            })

        if cipher_name.startswith("TLS_RSA_WITH_"):
            findings.append({
                "severity": "MEDIUM",
                "title": "Static RSA key exchange; no forward secrecy",
            })

        if "_CBC_" in cipher_name:
            findings.append({
                "severity": "MEDIUM",
                "title": "CBC-mode cipher suite accepted",
            })

        # TLS 1.3 ciphers do not encode key exchange in the cipher suite name,
        # so avoid falsely flagging TLS_AES_* or TLS_CHACHA20_* here.
        if (
            ephemeral_key is None
            and not cipher_name.startswith("TLS_AES")
            and "CHACHA20" not in cipher_name
        ):
            findings.append({
                "severity": "MEDIUM",
                "title": "No ephemeral key exchange detected",
            })

        return findings

    def _scan_attempt_result(
        self,
        scan_results: dict[str, Any],
        key: str,
    ) -> dict[str, Any] | None:
        attempt = scan_results.get(key)

        if not attempt:
            return None

        if attempt.get("status") != "COMPLETED":
            return None

        return attempt.get("result")

    def _add_finding(
        self,
        findings: list[dict[str, Any]],
        severity: str,
        title: str,
        description: str,
        evidence: dict[str, Any] | None = None,
    ):
        findings.append({
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": evidence or {},
        })

    def _parse_dt(self, value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def _expiry_severity(self, days_left: int) -> str:
        if days_left < 0:
            return "CRITICAL"  # expired
        if days_left <= 7:
            return "CRITICAL"  # urgent
        if days_left <= 30:
            return "HIGH"
        if days_left <= 60:
            return "MEDIUM"
        if days_left <= 90:
            return "LOW"
        return "INFO"