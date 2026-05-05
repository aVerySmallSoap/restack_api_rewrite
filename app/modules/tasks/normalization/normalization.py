import json
from pathlib import Path

from celery import shared_task
from pydantic import AnyUrl

from app.modules.tasks.web.attack_context import AttackContext
from app.modules.interfaces.types.reports import SARIFRule, SARIFResult
from app.modules.interfaces.types.context import redis_client
from app.modules.scanners.web.nuclei.nuclei_context import NucleiRecord, NucleiClassification, NucleiInfo
from app.modules.utils.utils import text_io_to_dict_list

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

def parse_zap_sarif_rules(attack_context: AttackContext) -> list[SARIFRule]:
    if attack_context.zap_result is None:
        return []
    zap_results = attack_context.zap_result
    zap_rules = zap_results["runs"][0]["tool"]["driver"]["rules"]
    returnable: list[SARIFRule] = []

    assert zap_rules is not None
    assert isinstance(zap_rules, list)
    for rule in zap_rules:
        assert rule is not None
        assert isinstance(rule, dict)
        assert rule["help"] is not None
        assert isinstance(rule["help"], dict)
        returnable.append(
            SARIFRule(
                id=rule["id"],
                name=rule["name"],
                short_description_text=rule.get("shortDescription", None),
                full_description_text=rule["fullDescription"].get("text", None),
                help_text=rule["help"].get("text", None),
                help_markdown=rule["help"].get("markdown", None),
                properties=rule.get("properties", None),
                level=rule.get("level", "info")
            )
        )
    return returnable

def parse_zap_sarif_results(attack_context: AttackContext) -> list[SARIFResult]:
    if attack_context.zap_result is None:
        return []
    zap_results = attack_context.zap_result
    zap_scan_results = zap_results["runs"][0]["results"]
    returnable: list[SARIFResult] = []

    assert zap_scan_results is not None
    assert isinstance(zap_scan_results, list)
    for result in zap_scan_results:
        assert result is not None
        assert isinstance(result, dict)
        returnable.append(
            SARIFResult(
                rule_id=result["ruleId"],
                message_text=result["message"]["text"],
                location=result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                properties=result["properties"],
            )
        )
    return returnable

def parse_wapiti_sarif_rules(attack_context: AttackContext) -> list[SARIFRule]:
    if attack_context.wapiti_result is None:
        return []
    wapiti_results = attack_context.wapiti_result
    wapiti_rules = wapiti_results["runs"][0]["tool"]["driver"]["rules"]
    returnable: list[SARIFRule] = []

    assert wapiti_rules is not None
    assert isinstance(wapiti_rules, list)
    for rule in wapiti_rules:
        assert rule is not None
        assert isinstance(rule, dict)
        assert rule["help"] is not None
        assert isinstance(rule["help"], dict)
        returnable.append(
            SARIFRule(
                id=rule["id"],
                name=rule["id"],
                short_description_text=rule["shortDescription"].get("text", None),
                full_description_text=rule["fullDescription"].get("text", None),
                help_text=rule["help"].get("text", None),
                help_markdown=rule["help"].get("markdown", None),
                properties=rule.get("properties", None),
                level=rule.get("level", "low"),
            )
        )
    return returnable

def parse_wapiti_sarif_results(attack_context: AttackContext) -> list[SARIFResult]:
    if attack_context.wapiti_result is None:
        return []
    wapiti_results = attack_context.wapiti_result
    wapiti_scan_results = wapiti_results["runs"][0]["results"]
    returnable: list[SARIFResult] = []

    assert wapiti_scan_results is not None
    assert isinstance(wapiti_scan_results, list)
    for result in wapiti_scan_results:
        assert result is not None
        assert isinstance(result, dict)
        returnable.append(
            SARIFResult(
                rule_id=result["ruleId"],
                message_text=result["message"]["text"],
                location=result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                properties=result["properties"]
            )
        )
    return returnable

def parse_nuclei_sarif_rules(attack_context: AttackContext) -> list[SARIFRule]:
    if attack_context.nuclei_result is None:
        return []
    nuclei_results = attack_context.nuclei_result
    nuclei_rules = nuclei_results["runs"][0]["tool"]["driver"]["rules"]
    returnable: list[SARIFRule] = []

    assert nuclei_rules is not None
    assert isinstance(nuclei_rules, list)
    for rule in nuclei_rules:
        assert rule is not None
        assert isinstance(rule, dict)
        assert rule["help"] is not None
        assert isinstance(rule["help"], dict)
        returnable.append(
            SARIFRule(
                id=rule["id"],
                name=rule["name"],
                short_description_text=rule.get("shortDescription", None),
                full_description_text=rule["fullDescription"].get("text", None),
                help_text=rule["help"].get("text", None),
                help_markdown=None,
                properties=rule.get("properties", None),
                level=rule.get("level", "info")
            )
        )
    return returnable

def parse_nuclei_sarif_results(attack_context: AttackContext) -> list[SARIFResult]:
    if attack_context.nuclei_result is None:
        return []
    nuclei_results = attack_context.nuclei_result
    nuclei_scan_results = nuclei_results["runs"][0]["results"]
    returnable: list[SARIFResult] = []

    assert nuclei_scan_results is not None
    assert isinstance(nuclei_scan_results, list)
    for result in nuclei_scan_results:
        assert result is not None
        assert isinstance(result, dict)
        assert result["message"] is not None
        returnable.append(
            SARIFResult(
                rule_id=result["ruleId"],
                message_text=result["message"]["text"] if result["message"]["text"] is not None else "",
                location=result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                properties=result["properties"],
            )
        )
    return returnable

# noinspection D
@shared_task(bind=True)
def task_basic_normalization(self, results: dict, session_id: str):
    # Everything here will be derived from Discovery and Attack Context
    raw = redis_client.get(f"attack:{session_id}")
    if raw is None:
        raise ValueError(f"Missing discovery context for session {session_id}")
    attack_context = AttackContext.model_validate_json(raw)
    assert isinstance(attack_context, AttackContext)

    # rules
    zap_rule_collection: list[SARIFRule] = parse_zap_sarif_rules(attack_context)
    wapiti_rule_collection: list[SARIFRule] = parse_wapiti_sarif_rules(attack_context)
    nuclei_rule_collection: list[SARIFRule] = parse_nuclei_sarif_rules(attack_context)

    # results
    zap_scan_results = parse_zap_sarif_results(attack_context)
    wapiti_scan_results = parse_wapiti_sarif_results(attack_context)
    nuclei_scan_results = parse_nuclei_sarif_results(attack_context)

    zap_scan_result_collection: list[SARIFResult] = []
    wapiti_scan_result_collection: list[SARIFResult] = []
    nuclei_scan_result_collection: list[SARIFResult] = []

    intersection_list: list[SARIFResult] = []
    union_list: list[SARIFResult] = []

    zap_mapped_rules = map_rules(zap_rule_collection)
    wapiti_mapped_rules = map_rules(wapiti_rule_collection)
    nuclei_mapped_rules = map_rules(nuclei_rule_collection)

    # match and compare zap and wapiti results
    for zap_result in zap_scan_result_collection:
            zap_rule = zap_mapped_rules.get(zap_result.rule_id)
            assert isinstance(zap_rule, SARIFRule)
            for wapiti_result in wapiti_scan_result_collection:
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
        for nuclei_result in nuclei_scan_result_collection:
            nuclei_rule = nuclei_mapped_rules.get(nuclei_result.rule_id)
            assert isinstance(nuclei_rule, SARIFRule)

            if nuclei_rule.properties["classification"] is None or \
                nuclei_rule.properties["classification"]["cwe-id"] is None:
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