from app.modules.interfaces.types.reports import SARIFRule, SARIFResult

def parse_zap_sarif_rules(data: dict) -> list[SARIFRule]:
    if data is None:
        return []
    zap_results = data
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

def parse_zap_sarif_rules_and_map(data: dict) -> dict[str, SARIFRule]:
    if data is None:
        return {}
    nuclei_results = data
    nuclei_rules = nuclei_results["runs"][0]["tool"]["driver"]["rules"]
    returnable: dict[str, SARIFRule] = {}

    for rule in nuclei_rules:
        short_desc = rule.get("shortDescription", None)
        if short_desc is not None:
            short_desc = short_desc.get("text", None)
        else:
            short_desc = None
        returnable[rule["id"]] = SARIFRule(
            id=rule["id"],
            name=rule["name"],
            short_description_text=short_desc,
            full_description_text=rule["fullDescription"].get("text", None),
            help_text=rule["help"].get("text", None),
            help_markdown=None,
            properties=rule.get("properties", None),
            level=rule.get("level", "info")
        )
    return returnable

def parse_zap_sarif_results(data: dict) -> list[SARIFResult]:
    if data is None:
        return []
    zap_results = data
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

def parse_wapiti_sarif_rules(data: dict) -> list[SARIFRule]:
    if data is None:
        return []
    wapiti_results = data
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

def parse_wapiti_sarif_rules_and_map(data: dict) -> dict[str, SARIFRule]:
    if data is None:
        return {}
    nuclei_results = data
    nuclei_rules = nuclei_results["runs"][0]["tool"]["driver"]["rules"]
    returnable: dict[str, SARIFRule] = {}

    for rule in nuclei_rules:
        short_desc = rule.get("shortDescription", None)
        if short_desc is not None:
            short_desc = short_desc.get("text", None)
        else:
            short_desc = None
        returnable[rule["id"]] = SARIFRule(
            id=rule["id"],
            name=rule["name"] if rule.get("name", None) else rule["id"],
            short_description_text=short_desc,
            full_description_text=rule["fullDescription"].get("text", None),
            help_text=rule["help"].get("text", None),
            help_markdown=None,
            properties=rule.get("properties", None),
            level=rule.get("level", "info")
        )
    return returnable

def parse_wapiti_sarif_results(data: dict) -> list[SARIFResult]:
    if data is None:
        return []
    wapiti_results = data
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

def parse_nuclei_sarif_rules(data: dict) -> list[SARIFRule]:
    if data is None:
        return []
    nuclei_results = data
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

def parse_nuclei_sarif_rules_and_map(data: dict) -> dict[str, SARIFRule]:
    if data is None:
        return {}
    nuclei_results = data
    nuclei_rules = nuclei_results["runs"][0]["tool"]["driver"]["rules"]
    returnable: dict[str, SARIFRule] = {}

    for rule in nuclei_rules:
        short_desc = rule.get("shortDescription", None)
        if short_desc is not None:
            short_desc = short_desc.get("text", None)
        else:
            short_desc = None
        returnable[rule["id"]] = SARIFRule(
            id=rule["id"],
            name=rule["name"],
            short_description_text=short_desc,
            full_description_text=rule["fullDescription"].get("text", None),
            help_text=rule["help"].get("text", None),
            help_markdown=None,
            properties=rule.get("properties", None),
            level=rule.get("level", "info")
        )
    return returnable


def parse_nuclei_sarif_results(data: dict) -> list[SARIFResult]:
    if data is None:
        return []
    nuclei_results = data
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