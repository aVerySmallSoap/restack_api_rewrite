import json
from datetime import datetime
from pathlib import Path

import tzlocal
from loguru import logger

from app.services.celery_app import celery_app
from app.modules.database.models.models import ScanReportModel
from app.modules.database.database import transaction
from app.modules.database.persistance.phases import mark_as_complete, mark_phase_as_errored
from app.modules.interfaces.enums.scan_tracking import ScanPhase


def summarize_with_ai(analytics_data: dict) -> dict:
    import json
    import os
    from google import genai
    from google.genai import types
    from loguru import logger

    ai_client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
    try:
        _data = {
            "union": analytics_data["data"]["union"],
            "intersection": analytics_data["data"]["intersection"],
            "rules": analytics_data["data"]["rules"]
        }
        _tech = {
            "fingerprinted": analytics_data["plugins"]["fingerprinted"],
            "patchable": analytics_data["plugins"]["patchable"]
        }

        vuln_response = ai_client.models.generate_content(
            model="gemini-2.5-flash",
            config=types.GenerateContentConfig(
                system_instruction="You are a cybersecurity specialist"
            ),
            contents=["Can you summarize the findings in this report.", "Can you recommend solutions on how to mitigate these problems", json.dumps(_data)]
        )

        tech_response = ai_client.models.generate_content(
            model="gemini-2.5-flash",
            config=types.GenerateContentConfig(
                system_instruction="You are a cybersecurity specialist. Ignore if there are empty technology fields"
            ),
            contents=["Can you summarize the findings in this report.", "If there are problems, can you recommend solutions to mitage them", json.dumps(_tech)]
        )
    except Exception as e:
        logger.error("Something happened!\n{}", e)
        return {}
    return {
        "summary": {
            "vulnerabilities": vuln_response.text,
            "tech": tech_response.text,
        }
    }

#noinspection D
def generate_summary_stats(analytics_data: dict) -> dict:
    """Generate executive summary statistics"""

    union_results = analytics_data["data"]["union"]
    intersection_results = analytics_data["data"]["intersection"]

    # Calculate Total
    total_vulns = sum(len(r) for r in union_results) + len(intersection_results)

    # Reset counters
    high_confidence_count = 0
    medium_confidence_count = 0
    low_confidence_count = 0
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    # FIX: Use a helper to count BOTH Union AND Intersection lists
    def process_vuln_dict(vulnerability: dict):
        nonlocal high_confidence_count, medium_confidence_count, low_confidence_count
        # 1. Count Severity
        severity = vulnerability.get("level", "Low")
        if severity == "error":
            severity_counts["High"] += 1
        elif severity == "warning":
            severity_counts["Medium"] += 1
        elif severity == "note":
            severity_counts["Low"] += 1

        # 2. Count Confidence
        confidence = vulnerability.get("properties", {}).get("analytics", {}).get("confidence", "Low")
        conf_lower = str(confidence).lower()
        if conf_lower in ["high", "confirmed", "critical"]:
            high_confidence_count += 1
        elif conf_lower in ["medium", "warning"]:
            medium_confidence_count += 1
        else:
            low_confidence_count += 1
    def process_vuln_list(vulnerabilities: list):
        nonlocal high_confidence_count, medium_confidence_count, low_confidence_count
        for vulnerability in vulnerabilities:
            # 1. Count Severity
            severity = vulnerability.get("level", "Low")
            if severity == "error":
                severity_counts["High"] += 1
            elif severity == "warning":
                severity_counts["Medium"] += 1
            elif severity == "note":
                severity_counts["Low"] += 1

            # 2. Count Confidence
            confidence = vulnerability.get("properties", {}).get("analytics", {}).get("confidence", "Low")
            conf_lower = str(confidence).lower()
            if conf_lower in ["high", "confirmed", "critical"]:
                high_confidence_count += 1
            elif conf_lower in ["medium", "warning"]:
                medium_confidence_count += 1
            else:
                low_confidence_count += 1


    # Loop through ALL results (Union Lists + Intersection List)
    for scanner_results in union_results:
        process_vuln_dict(scanner_results)

    # THIS WAS MISSING BEFORE:
    process_vuln_list(intersection_results)

    # Calculate Rates
    confidence_rate = 0
    if total_vulns > 0:
        weighted = (high_confidence_count * 1.0) + (medium_confidence_count * 0.5) + (low_confidence_count * 0.1)
        confidence_rate = (weighted / total_vulns) * 100

    agreement_rate = (high_confidence_count / total_vulns) * 100 if total_vulns > 0 else 0

    return {
        "total_vulnerabilities": total_vulns,
        "high_confidence_vulns": high_confidence_count,
        "medium_confidence_vulns": medium_confidence_count,
        "low_confidence_vulns": low_confidence_count,
        "confidence_rate": f"{confidence_rate:.1f}%",
        "severity_breakdown": severity_counts,
        "critical_count": severity_counts["Critical"] + severity_counts["High"],
        "scanner_agreement_rate": f"{agreement_rate:.1f}%"
    }

def create_priority_matrix(analytics_data: dict) -> dict:
    matrix = {
        "high_severity_high_confidence": [],
        "high_severity_low_confidence": [],
        "low_severity_high_confidence": [],
        "low_severity_low_confidence": []
    }

    # Helper to categorize
    def categorize_vuln(vuln):
        severity = vuln.get("level", "Low")
        confidence = vuln.get("properties", {}).get("analytics", {}).get("confidence", "Low")

        is_high_conf = str(confidence).lower() in ["high", "confirmed", "critical"]
        is_high_sev = severity in ["error", "High", "Critical"]

        if is_high_sev and is_high_conf:
            matrix["high_severity_high_confidence"].append(vuln)
        elif is_high_sev and not is_high_conf:
            matrix["high_severity_low_confidence"].append(vuln)
        elif not is_high_sev and is_high_conf:
            matrix["low_severity_high_confidence"].append(vuln)
        else:
            matrix["low_severity_low_confidence"].append(vuln)

    # Process Intersection (Always High Confidence)
    for vuln in analytics_data["data"]["intersection"]:
        categorize_vuln(vuln)

    # Process Individual Results
    for scanner_results in analytics_data["data"]["individual_results"]:
        for vuln in scanner_results:
            categorize_vuln(vuln)

    return {
        "matrix": matrix,
        "quadrant_counts": {k: len(v) for k, v in matrix.items()}
    }

def compute_and_attach_analytics(report: ScanReportModel | None, analytics_data: dict, session_name: str):
    """
    Compute analytics from analysis data and attach to report object.
    Call this BEFORE session.commit() so all data is saved atomically.
    """
    try:
        # 1. Generate Summary Statistics
        stats = generate_summary_stats(analytics_data)
        high_confidence_vulns = stats.get("high_confidence_vulns", 0)
        medium_confidence_vulns = stats.get("medium_confidence_vulns", 0)
        low_confidence_vulns = stats.get("low_confidence_vulns", 0)

        agreement_str = stats.get("scanner_agreement_rate", "0%")
        confidence_str = stats.get("confidence_rate", "0%")

        scanner_agreement_rate = float(agreement_str.rstrip('%')) if agreement_str else 0.0
        confidence_rate = float(confidence_str.rstrip('%')) if confidence_str else 0.0

        # 2. Generate Priority Matrix
        matrix_data = create_priority_matrix(analytics_data)
        high_severity_high_confidence = matrix_data["quadrant_counts"]["high_severity_high_confidence"]
        high_severity_low_confidence = matrix_data["quadrant_counts"]["high_severity_low_confidence"]
        low_severity_high_confidence = matrix_data["quadrant_counts"]["low_severity_high_confidence"]
        low_severity_low_confidence = matrix_data["quadrant_counts"]["low_severity_low_confidence"]

        # 3. Generate AI Summary (if available)
        ai_summary = None
        ai_summary_vulnerabilities = None
        ai_summary_tech = None
        try:
            ai_summary = summarize_with_ai(analytics_data)
            if ai_summary and "summary" in ai_summary:
                pass
                ai_summary_vulnerabilities = ai_summary["summary"].get("vulnerabilities", "")
                ai_summary_tech = ai_summary["summary"].get("tech", "")
        except Exception as e:
            logger.warning(f"AI summary generation failed for {session_name}: {e}")
            ai_summary_vulnerabilities = None
            ai_summary_tech = None

        # return report
        with open(f"{Path.cwd()}/app/reports/test_analytics_{session_name}.json", "w") as f:
            f.write(
                json.dumps(
                    {
                        "stats": stats,
                        "matrix": matrix_data,
                        "ai_summary": ai_summary,
                    },
                    indent=4
                )
            )

        with transaction() as db:
            db.add(
                ScanReportModel(
                    scan_id=session_name,
                    total_vulnerabilities=len(analytics_data["data"]["union"]),
                    scanner="all", # TODO: Find a way to generate this dynamically
                    critical_count=0,
                    scan_date=datetime.now(tz=tzlocal.get_localzone()),
                    scan_type="full",
                    ai_summary_vulnerabilities=ai_summary_vulnerabilities,
                    ai_summary_tech=ai_summary_tech,
                    high_severity_high_confidence=high_severity_high_confidence,
                    high_severity_low_confidence=high_severity_low_confidence,
                    low_severity_high_confidence=low_severity_high_confidence,
                    low_severity_low_confidence=low_severity_low_confidence,
                    scanner_agreement_rate=scanner_agreement_rate,
                    confidence_rate=confidence_rate,
                    high_confidence_vulns=high_confidence_vulns,
                    medium_confidence_vulns=medium_confidence_vulns,
                    low_confidence_vulns=low_confidence_vulns
            ))

        mark_as_complete(
            report_id=session_name,
            phase=ScanPhase.ANALYSIS
        )
        return {
            "stats": stats,
            "matrix": matrix_data,
            "ai_summary": ai_summary,
        }
    except Exception as e:
        logger.error(f"Error computing analytics")
        logger.exception(e)
        raise

@celery_app.task(
    bind=True,
    soft_time_limit=240,
    time_limit=300,
)
def task_generate_report_analytics(self, result: dict, session_name: str):
    try:
        report_data = compute_and_attach_analytics(None, result, session_name)
        with open(f"{Path.cwd()}/app/reports/{session_name}.json", "w") as f:
            f.write(json.dumps(report_data, indent=4))
    except Exception as e:
        logger.exception(e)
        mark_phase_as_errored(
            report_id=session_name,
            phase=ScanPhase.ANALYSIS,
        )
        raise