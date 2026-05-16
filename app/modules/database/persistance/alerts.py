"""
Helpers for inserting alerts from different scanners
"""
from datetime import datetime
import tzlocal

from app.modules.utils.sarif_utils import parse_nuclei_sarif_results, parse_nuclei_sarif_rules_and_map, \
    parse_wapiti_sarif_rules_and_map, parse_wapiti_sarif_results
from app.modules.interfaces.types.reports import SARIFResult, SARIFRule
from app.modules.database.database import transaction
from app.modules.database.models.findings import VulnerabilityModel
from app.modules.utils.sarif_utils import parse_zap_sarif_rules_and_map, parse_zap_sarif_results


def insert_zap_alerts(data: dict, session_id: str):
    rules: dict[str, SARIFRule] = parse_zap_sarif_rules_and_map(data)
    results: list[SARIFResult] = parse_zap_sarif_results(data)
    findings: list[VulnerabilityModel] = []

    with transaction() as db:
        for result in results:
            _rule = rules.get(result.rule_id, None)
            if _rule is None:
                continue
            findings.append(
                VulnerabilityModel(
                    scan_id=session_id,  # This always assumes that the scan_id is the session id
                    scan_date=datetime.now(tz=tzlocal.get_localzone()),
                    scanner="zap",
                    vulnerability_type=_rule.id,
                    severity=_rule.level,
                    confidence=result.properties.get("confidence", None),
                    http_request=result.properties.get("har", None),
                    description=_rule.full_description_text if _rule.full_description_text else "",
                    endpoint=result.location,
                    remediation_effort=(
                        _rule.help_text if isinstance(_rule.help_text, str) else _rule.help_text[
                            0] if _rule.help_text else ""
                    ),
                    method=_rule.properties.get("method", None),
                    state=None,
                    blob=result.model_dump(),
                )
            )
        db.add_all(findings)

def insert_wapiti_alerts(data: dict, session_id: str):
    rules: dict[str, SARIFRule] = parse_wapiti_sarif_rules_and_map(data)
    results: list[SARIFResult] = parse_wapiti_sarif_results(data)
    findings: list[VulnerabilityModel] = []

    with transaction() as db:
        for result in results:
            _rule = rules.get(result.rule_id, None)
            if _rule is None:
                continue
            findings.append(
                VulnerabilityModel(
                    scan_id=session_id,  # This always assumes that the scan_id is the session id
                    scan_date=datetime.now(tz=tzlocal.get_localzone()),
                    scanner="wapiti",
                    vulnerability_type=_rule.id,
                    severity=_rule.level,
                    confidence=_rule.properties.get("confidence", "low"),
                    http_request=result.properties.get("http_request", None),
                    description=_rule.full_description_text if _rule.full_description_text else "",
                    endpoint=result.location,
                    remediation_effort=(
                        _rule.help_text if isinstance(_rule.help_text, str) else _rule.help_text[
                            0] if _rule.help_text else ""
                    ),
                    method=_rule.properties.get("method", None),
                    state=None,
                    blob=result.model_dump(),
                )
            )
        db.add_all(findings)

def insert_nuclei_alerts(data: dict, session_id: str):
    rules:dict[str, SARIFRule] = parse_nuclei_sarif_rules_and_map(data)
    results:list[SARIFResult] = parse_nuclei_sarif_results(data)
    findings: list[VulnerabilityModel] = []

    with transaction() as db:
        for result in results:
            _rule = rules.get(result.rule_id, None)
            if _rule is None:
                continue
            findings.append(
                VulnerabilityModel(
                    scan_id=session_id, # This always assumes that the scan_id is the session id
                    scan_date=datetime.now(tz=tzlocal.get_localzone()),
                    scanner="nuclei",
                    vulnerability_type=_rule.id,
                    severity=_rule.level,
                    confidence="high", # nuclei results are template based, so if it returns, there is a high possibility of it existing
                    http_request=result.properties.get("request", None),
                    description=_rule.full_description_text if _rule.full_description_text else "",
                    endpoint=result.location,
                    remediation_effort=(
                        _rule.help_text if isinstance(_rule.help_text, str) else _rule.help_text[0] if _rule.help_text else ""
                    ),
                    method=_rule.properties.get("method", None),
                    state=None,
                    blob=result.model_dump(),
                )
            )
        db.add_all(findings)