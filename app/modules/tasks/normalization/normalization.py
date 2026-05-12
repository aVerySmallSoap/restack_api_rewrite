import json
from pathlib import Path

from celery import shared_task

from app.modules.tasks.web.attack_context import AttackContext
from app.modules.interfaces.types.reports import SARIFRule, SARIFResult
from app.modules.interfaces.types.context import redis_client
from app.modules.utils.sarif_utils import parse_zap_sarif_rules, parse_wapiti_sarif_rules, \
    parse_nuclei_sarif_rules, parse_zap_sarif_results, parse_wapiti_sarif_results, parse_nuclei_sarif_results

PROJECT_ROOT = Path.cwd().parent.parent.parent.parent

def map_rules(rules: list[SARIFRule]) -> dict:
    rule_dict: dict = {}
    for rule in rules or []:
        if rule.id:
            rule_dict[rule.id] = rule
    return rule_dict

def calculate_risk_score(vulnerability: SARIFResult, rule: SARIFRule, intersected: bool) -> dict:
    severity_map = {
        "Critical": 10, "High": 9, "error": 9,
        "warning": 6, "Medium": 6, "Low": 6, "note": 3,
        "Informational": 1, "info": 1
    }
    confidence_map = {
        "High": 3, "Confirmed": 3, "Medium": 2, "Low": 1
    }

    severity = rule.level
    confidence = vulnerability.properties.get("confidence", "Low")

    severity_score = severity_map.get(severity, 3)
    confidence_score = confidence_map.get(confidence, 1)
    agreement_bonus = 2 if intersected else 0

    risk_score = severity_score + confidence_score + agreement_bonus

    # Determine priority label
    priority = "low"
    if risk_score >= 12:
        priority = "critical"
    elif risk_score >= 9:
        priority = "high"
    elif risk_score >= 6:
        priority = "medium"

    return {
        "risk_score": risk_score,
        "priority": priority,
        "severity": severity,
        "confidence": confidence
    }

# noinspection D
@shared_task(bind=True)
def task_basic_normalization(self, results: dict, session_id: str):
    # TODO: define failure states
    # Everything here will be derived from Discovery and Attack Context
    raw = redis_client.get(f"attack:{session_id}")
    if raw is None:
        raise ValueError(f"Missing discovery context for session {session_id}")
    attack_context = AttackContext.model_validate_json(raw)
    assert isinstance(attack_context, AttackContext)

    # rules
    zap_rule_collection: list[SARIFRule] = parse_zap_sarif_rules(attack_context.zap_result)
    wapiti_rule_collection: list[SARIFRule] = parse_wapiti_sarif_rules(attack_context.wapiti_result)
    nuclei_rule_collection: list[SARIFRule] = parse_nuclei_sarif_rules(attack_context.nuclei_result)

    # results
    zap_scan_results = parse_zap_sarif_results(attack_context.zap_result)
    wapiti_scan_results = parse_wapiti_sarif_results(attack_context.wapiti_result)
    nuclei_scan_results = parse_nuclei_sarif_results(attack_context.nuclei_result)

    intersection_list: list[SARIFResult] = []
    union_list: list[SARIFResult] = []

    zap_mapped_rules = map_rules(zap_rule_collection)
    wapiti_mapped_rules = map_rules(wapiti_rule_collection)
    nuclei_mapped_rules = map_rules(nuclei_rule_collection)

    # match and compare zap and wapiti results
    for zap_result in zap_scan_results:
            zap_rule = zap_mapped_rules.get(zap_result.rule_id)
            assert isinstance(zap_rule, SARIFRule)
            for wapiti_result in wapiti_scan_results:
                wapiti_rule = wapiti_mapped_rules.get(wapiti_result.rule_id)
                assert isinstance(wapiti_rule, SARIFRule)

                wapiti_tags = wapiti_rule.properties["tags"]
                for tag in wapiti_tags:
                    if "CWE-" in tag:
                        wapiti_cwe_int = int(str.split(tag, "-")[1])
                        zap_cwe = zap_rule.properties["cwe"]
                        if zap_cwe and int(zap_cwe) == wapiti_cwe_int and zap_result.location == wapiti_result.location:
                            zap_result.properties["analytics"] = calculate_risk_score(vulnerability=zap_result, rule=zap_rule, intersected=True)
                            wapiti_result.properties["analytics"] = calculate_risk_score(vulnerability=wapiti_result, rule=wapiti_rule, intersected=True)
                            intersection_list.append(zap_result)
                        else:
                            zap_result.properties["analytics"] = calculate_risk_score(zap_result, zap_rule, False)
                            wapiti_result.properties["analytics"] = calculate_risk_score(wapiti_result, wapiti_rule, False)
                            union_list.append(zap_result)
                            union_list.append(wapiti_result)
                        # if zap_result in zap_scan_results: zap_scan_results.remove(zap_result)
                        # if wapiti_result in wapiti_scan_results: wapiti_scan_results.remove(wapiti_result)

            if "analytics" not in zap_rule.properties:
                zap_result.properties["analytics"] = calculate_risk_score(zap_result, zap_rule, False)

    # match and compare intersected results to nuclei results
    # This does nothing btw
    for intersection_result in intersection_list:
        zap_rule = zap_mapped_rules.get(intersection_result.rule_id)
        for nuclei_result in nuclei_scan_results:
            nuclei_rule = nuclei_mapped_rules.get(nuclei_result.rule_id)
            assert isinstance(nuclei_rule, SARIFRule)

            if nuclei_rule.properties["classification"] is None or \
                nuclei_rule.properties["classification"].get("cwe-id", None) is None:
                nuclei_result.properties["analytics"] = calculate_risk_score(nuclei_result, nuclei_rule, False)
                union_list.append(nuclei_result)
            else: # classification is not None && classification:cwe-id exists
                if isinstance(nuclei_rule.properties["classification"]["cwe-id"], list):
                    nuclei_tag = str.upper(nuclei_rule.properties["classification"]["cwe-id"][0])

                    if "CWE-" in nuclei_tag:
                        nuclei_cwe = int(nuclei_tag.split("-")[1])
                        zap_cwe = zap_rule.properties["cwe"]
                        if zap_cwe and int(zap_cwe) == nuclei_cwe and intersection_result.location == nuclei_result.location:
                            nuclei_result.properties["analytics"] = calculate_risk_score(nuclei_result, nuclei_rule, True)
                        else:
                            nuclei_result.properties["analytics"] = calculate_risk_score(nuclei_result, nuclei_rule, False)
                            union_list.append(nuclei_result)
                        # if nuclei_result in nuclei_scan_results: nuclei_scan_results.remove(nuclei_result)

    individual_results = [
        [entry.model_dump(mode="json") for entry in wapiti_scan_results],
        [entry.model_dump(mode="json") for entry in zap_scan_results],
        [entry.model_dump(mode="json") for entry in nuclei_scan_results],
    ]

    data = {
        "data": {
            "union": [entry.model_dump(mode="json") for entry in union_list],
            "intersection": [entry.model_dump(mode="json") for entry in intersection_list],
            "individual_results": individual_results,
            "rules": {
                "zap": [entry.model_dump(mode="json") for entry in zap_rule_collection],
                "wapiti": [entry.model_dump(mode="json") for entry in wapiti_rule_collection],
                "nuclei": [entry.model_dump(mode="json") for entry in nuclei_rule_collection],
            }
        },
        "plugins": {
            "fingerprinted": [entry.model_dump(mode="json") for entry in attack_context.discovery_context.technologies],
            "patchable": attack_context.discovery_context.queried_vulnerabilities
        }
    }

    redis_client.set(f"normalization:{session_id}", json.dumps(data))
    return data