# Generate reports based on system results
# Outputs: PDF and Excel
#
# STRUCTURE
#   NUMBER OF VULNERABILITIES DETECTED
#   AI SUMMARY OF RESULTS
#   AI RECOMMENDATIONS BASED ON RESULTS
#   SCAN DETAILS         — Domain, Tools, Total Vulns, Scan Date, Scan Type
#   TECHNOLOGIES TABLE   — Technology | Version | CVEs
#   VULNERABILITIES      — Type | Tool | Endpoint | Severity | Confidence
#   CRAWLED URLS         — All endpoints discovered during crawl
#   SSL / TLS FINDINGS   — Certificate and protocol findings from SSLyze

import html
import os
import re
from pathlib import Path

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
)
from sqlalchemy import select

from app.modules.database.database import transaction
from app.modules.database.models.context import DiscoveryContextModel
from app.modules.database.models.findings import TechnologiesModel, VulnerabilityModel
from app.modules.database.models.models import Scan, ScanReportModel

# ---------------------------------------------------------------------------
# Severity helpers
# Scanners all store SARIF levels via the insert_*_alerts pipeline:
#   "error"   = High/Critical
#   "warning" = Medium
#   "note"    = Low
#   "info"    = Informational
# Human-readable values kept as fallback for any manually-inserted rows.
# ---------------------------------------------------------------------------

SEVERITY_LABEL: dict[str, str] = {
    "error":         "High",
    "warning":       "Medium",
    "note":          "Low",
    "none":          "Info",
    "info":          "Info",
    "Critical":      "Critical",
    "High":          "High",
    "Medium":        "Medium",
    "Low":           "Low",
    "Info":          "Info",
    "Informational": "Info",
}

SEVERITY_ORDER: dict[str, int] = {
    "Critical": 0, "error": 0,
    "High":     1,
    "Medium":   2, "warning": 2,
    "Low":      3, "note": 3,
    "Info":     4, "Informational": 4, "none": 4, "info": 4,
}

EXCLUDED_TECH = ["HTML", "HTML5"]


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------

def _sanitize_for_pdf(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", text)
    text = html.escape(text, quote=False)
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"__(.+?)__",     r"<b>\1</b>", text)
    text = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"<i>\1</i>", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    text = re.sub(r"^#{1,6}\s+(.+)$", r"\n<b>\1</b>", text, flags=re.MULTILINE)
    text = re.sub(r"^-{3,}$", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*[\*\-]\s+", "  • ", text, flags=re.MULTILINE)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _safe_str(value) -> str:
    if isinstance(value, list):
        return value[0] if value else "N/A"
    return str(value) if value is not None else "N/A"


def _extract_cves(data: dict | None) -> str:
    if not data or not isinstance(data, dict):
        return "N/A"
    for key in ("cves", "cve", "CVEs", "CVE", "cve_ids"):
        val = data.get(key)
        if val:
            if isinstance(val, list):
                return ", ".join(str(v) for v in val)
            return str(val)
    return "N/A"


# ---------------------------------------------------------------------------
# Data parsers
# ---------------------------------------------------------------------------

def _parse_technologies(tech_rows) -> list[dict]:
    """Convert TechnologiesModel rows to plain dicts, deduplicated."""
    tech_list: list[dict] = []
    seen: set = set()
    for t in tech_rows:
        if t.name in EXCLUDED_TECH:
            continue
        if t.version:
            version_str = (
                ", ".join(str(v) for v in t.version if v)
                if isinstance(t.version, list)
                else str(t.version)
            ) or "N/A"
        else:
            version_str = "N/A"
        key = (t.name, version_str)
        if key not in seen:
            seen.add(key)
            tech_list.append({"Technology": t.name, "Version": version_str})
    return tech_list


def _serialise_vulns(vuln_results) -> list[dict]:
    """
    Convert VulnerabilityModel rows to plain dicts.
    All scanners included — no severity filter — sorted most-severe first.
    """
    rows = []
    for v in vuln_results:
        label = SEVERITY_LABEL.get(v.severity, v.severity)
        rows.append({
            "Type":        v.vulnerability_type,
            "Severity":    label,
            "Confidence":  v.confidence or "N/A",
            "Scanner":     v.scanner,
            "Endpoint":    v.endpoint,
            "Description": v.description or "",
            "Fix":         v.remediation_effort or "",
            "CVEs":        _extract_cves(v.blob if isinstance(v.blob, dict) else {}),
            "_sort":       SEVERITY_ORDER.get(v.severity, 99),
        })
    rows.sort(key=lambda r: r["_sort"])
    for r in rows:
        del r["_sort"]
    return rows


def _parse_ssl_findings(ssl_certs: dict | None) -> list[dict]:
    """Extract SSLyze findings from the discovery context ssl_certs blob."""
    if not ssl_certs or not isinstance(ssl_certs, dict):
        return []
    findings = ssl_certs.get("findings", [])
    if not isinstance(findings, list):
        return []
    rows = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        rows.append({
            "Severity":    f.get("severity", "INFO"),
            "Title":       f.get("title", ""),
            "Description": f.get("description", ""),
        })
    rows.sort(key=lambda r: SEVERITY_ORDER.get(r["Severity"], 99))
    return rows


def _parse_crawled_urls(endpoints: list | None) -> list[str]:
    if not endpoints or not isinstance(endpoints, list):
        return []
    return sorted(set(str(e) for e in endpoints if e))


# ---------------------------------------------------------------------------
# Excel
# ---------------------------------------------------------------------------

def generate_excel(report_id: str) -> dict:
    """
    Generate an Excel workbook for the given report_id.
    Sheets: Summary | Scan Details | Vulnerabilities | Technologies | Crawled URLs | SSL Findings
    """
    file_name = f"Restack_Report_{report_id}.xlsx"
    output_path = os.path.join(f"{Path.cwd()}/reports/excel/", file_name)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with transaction() as session:
        scan = session.scalars(
            select(Scan).where(Scan.id == report_id)
        ).first()
        if not scan:
            return {"error": f"No scan found for report_id: {report_id}"}

        report = session.scalars(
            select(ScanReportModel).where(ScanReportModel.scan_id == str(report_id))
        ).first()

        discovery = session.scalars(
            select(DiscoveryContextModel).where(
                DiscoveryContextModel.scan_id == str(report_id)
            )
        ).first()

        tech_rows = session.scalars(
            select(TechnologiesModel).where(
                TechnologiesModel.scan_id == str(report_id)
            )
        ).all()
        tech_list = _parse_technologies(tech_rows)

        # All vulnerabilities — no severity filter
        vuln_rows = session.scalars(
            select(VulnerabilityModel).where(
                VulnerabilityModel.scan_id == str(report_id)
            )
        ).all()
        vulns = _serialise_vulns(vuln_rows)

        # Snapshot scalars before session closes
        target_url   = scan.target_url
        scan_date    = scan.scan_date.strftime("%Y-%m-%d %H:%M:%S")
        scan_type    = scan.scan_type
        scanner      = report.scanner if report else "N/A"
        total_vulns  = report.total_vulnerabilities if report else len(vulns)
        critical_cnt = report.critical_count if report else 0
        ai_vuln_summary = (
            report.ai_summary_vulnerabilities
            if report and report.ai_summary_vulnerabilities
            else "AI summary not yet available."
        )
        ai_tech_summary = (
            report.ai_summary_tech
            if report and report.ai_summary_tech
            else "AI technology summary not yet available."
        )

        # Discovery data
        crawled_urls = _parse_crawled_urls(
            discovery.endpoints if discovery else None
        )
        ssl_findings = _parse_ssl_findings(
            discovery.ssl_certs if discovery else None
        )
        ports = discovery.ports if discovery and discovery.ports else []

    # --- DataFrames ---

    summary_df = pd.DataFrame({
        "Category":    ["Vulnerability Summary", "Technology Summary"],
        "AI Analysis": [ai_vuln_summary, ai_tech_summary],
    })

    scan_df = pd.DataFrame({
        "Scan Detail": [
            "Target URL", "Scan Type", "Scanner(s) Used",
            "Scan Date", "Total Vulnerabilities", "Critical / High Count",
            "Open Ports",
        ],
        "Value": [
            target_url, scan_type, scanner,
            scan_date, total_vulns, critical_cnt,
            ", ".join(str(p) for p in ports) if ports else "N/A",
        ],
    })

    vuln_df = (
        pd.DataFrame(vulns)
        if vulns
        else pd.DataFrame(
            columns=["Type", "Severity", "Confidence", "Scanner",
                     "Endpoint", "Description", "Fix", "CVEs"]
        )
    )

    tech_df = (
        pd.DataFrame(tech_list)
        if tech_list
        else pd.DataFrame(columns=["Technology", "Version"])
    )

    urls_df = (
        pd.DataFrame({"Crawled URL": crawled_urls})
        if crawled_urls
        else pd.DataFrame(columns=["Crawled URL"])
    )

    ssl_df = (
        pd.DataFrame(ssl_findings)
        if ssl_findings
        else pd.DataFrame(columns=["Severity", "Title", "Description"])
    )

    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        for df, sheet in [
            (summary_df, "Summary"),
            (scan_df,    "Scan Details"),
            (vuln_df,    "Vulnerabilities"),
            (tech_df,    "Technologies"),
            (urls_df,    "Crawled URLs"),
            (ssl_df,     "SSL Findings"),
        ]:
            df.to_excel(writer, sheet_name=sheet, index=False)

        for _sheet_name, worksheet in writer.sheets.items():
            for col in worksheet.columns:
                max_len = max(
                    (len(str(cell.value)) for cell in col if cell.value is not None),
                    default=10,
                )
                worksheet.column_dimensions[col[0].column_letter].width = min(max_len + 4, 80)

    return {"message": "Excel report generated successfully", "path": output_path}


# ---------------------------------------------------------------------------
# PDF helpers
# ---------------------------------------------------------------------------

def _footer_only(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#CCCCCC"))
    canvas.setLineWidth(0.5)
    canvas.line(inch, 0.6 * inch, letter[0] - inch, 0.6 * inch)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#888888"))
    canvas.drawString(inch, 0.4 * inch, "Restack Report")
    canvas.drawRightString(letter[0] - inch, 0.4 * inch, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()


def _plain_table_style(header_row: bool = True) -> TableStyle:
    ACCENT     = colors.HexColor("#2C3E50")
    HEADER_BG  = colors.HexColor("#F2F4F5")
    GRID_COLOR = colors.HexColor("#DDDDDD")

    base = [
        ("ALIGN",         (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("LEADING",       (0, 0), (-1, -1), 13),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("LINEBELOW",     (0, 0), (-1, -2), 0.4, GRID_COLOR),
        ("BOX",           (0, 0), (-1, -1), 0.5, GRID_COLOR),
    ]
    if header_row:
        base += [
            ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
            ("TEXTCOLOR",  (0, 0), (-1, 0), ACCENT),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, 0), 8.5),
            ("LINEBELOW",  (0, 0), (-1, 0), 1, ACCENT),
        ]
    return TableStyle(base)


def _severity_color(label: str) -> colors.HexColor:
    return {
        "Critical": colors.HexColor("#C0392B"),
        "High":     colors.HexColor("#E74C3C"),
        "Medium":   colors.HexColor("#E67E22"),
        "Low":      colors.HexColor("#3498DB"),
    }.get(label, colors.HexColor("#888888"))


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def generate_pdf(report_id: str) -> dict:
    """Generate a minimal, print-ready PDF report for the given report_id."""
    file_name = f"Restack_Report_{report_id}.pdf"
    output_path = os.path.join(f"{Path.cwd()}/reports/pdfs/", file_name)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # ------------------------------------------------------------------
    # 1. Fetch all data inside a single session, serialise immediately
    # ------------------------------------------------------------------
    with transaction() as session:
        scan = session.scalars(
            select(Scan).where(Scan.id == report_id)
        ).first()
        if not scan:
            return {"error": f"No scan found for report_id: {report_id}"}

        report = session.scalars(
            select(ScanReportModel).where(ScanReportModel.scan_id == str(report_id))
        ).first()

        discovery = session.scalars(
            select(DiscoveryContextModel).where(
                DiscoveryContextModel.scan_id == str(report_id)
            )
        ).first()

        tech_rows = session.scalars(
            select(TechnologiesModel).where(
                TechnologiesModel.scan_id == str(report_id)
            )
        ).all()
        tech_list = _parse_technologies(tech_rows)

        # All vulnerabilities — no severity filter
        vuln_rows = session.scalars(
            select(VulnerabilityModel).where(
                VulnerabilityModel.scan_id == str(report_id)
            )
        ).all()
        vulns = _serialise_vulns(vuln_rows)

        # Snapshot scalars before session closes
        target_url   = scan.target_url
        scan_date    = scan.scan_date.strftime("%Y-%m-%d %H:%M:%S")
        scan_type    = scan.scan_type
        scanner      = report.scanner if report else "N/A"
        total_vulns  = report.total_vulnerabilities if report else len(vulns)
        critical_cnt = report.critical_count if report else 0

        # Discovery data
        crawled_urls = _parse_crawled_urls(
            discovery.endpoints if discovery else None
        )
        ssl_findings = _parse_ssl_findings(
            discovery.ssl_certs if discovery else None
        )
        ssl_summary = (
            discovery.ssl_certs.get("summary", {})
            if discovery and isinstance(discovery.ssl_certs, dict)
            else {}
        )
        ports = discovery.ports if discovery and discovery.ports else []

    # ------------------------------------------------------------------
    # 2. Styles
    # ------------------------------------------------------------------
    ACCENT = colors.HexColor("#2C3E50")
    styles = getSampleStyleSheet()

    style_title = ParagraphStyle(
        "ReportTitle", parent=styles["Title"],
        fontSize=22, leading=26, spaceAfter=2,
        textColor=ACCENT, alignment=TA_LEFT, fontName="Helvetica-Bold",
    )
    style_meta = ParagraphStyle(
        "ReportMeta", parent=styles["Normal"],
        fontSize=9, textColor=colors.HexColor("#555555"), spaceAfter=3,
    )
    style_h2 = ParagraphStyle(
        "SectionHeading", parent=styles["Heading2"],
        fontSize=11, leading=14, textColor=ACCENT,
        spaceBefore=20, spaceAfter=6, fontName="Helvetica-Bold",
    )
    style_body = ParagraphStyle(
        "BodyText", parent=styles["Normal"],
        fontSize=9, leading=13, textColor=colors.HexColor("#333333"),
    )
    style_cell = ParagraphStyle(
        "CellText", parent=styles["Normal"],
        fontSize=8, leading=11, textColor=colors.HexColor("#333333"),
    )
    style_url = ParagraphStyle(
        "URLText", parent=styles["Normal"],
        fontSize=7.5, leading=10, textColor=colors.HexColor("#2980B9"),
    )
    style_disclaimer = ParagraphStyle(
        "Disclaimer", parent=styles["Normal"],
        fontSize=7, leading=10,
        textColor=colors.HexColor("#999999"), alignment=TA_CENTER,
    )

    def hr():
        return HRFlowable(
            width="100%", thickness=0.5,
            color=colors.HexColor("#DDDDDD"), spaceAfter=8,
        )

    def accent_hr():
        return HRFlowable(
            width="100%", thickness=1.5, color=ACCENT, spaceAfter=10,
        )

    # ------------------------------------------------------------------
    # 3. Build elements
    # ------------------------------------------------------------------
    elements = []

    # Title block
    elements.append(Paragraph("Restack Report", style_title))
    elements.append(accent_hr())
    elements.append(Paragraph(f"<b>Target:</b> {target_url}", style_meta))
    elements.append(Paragraph(f"<b>Date:</b> {scan_date}", style_meta))
    elements.append(Paragraph(
        f"<b>Total issues:</b> {len(vulns)}  |  "
        f"<b>Critical / High:</b> {critical_cnt}",
        style_meta,
    ))
    elements.append(Spacer(1, 16))

    # -- Scan Details --
    elements.append(Paragraph("Scan Info", style_h2))
    elements.append(hr())

    port_str = ", ".join(str(p) for p in ports) if ports else "N/A"
    scan_table_data = [
        ["",                      ""],
        ["Website",               target_url],
        ["Scan Date",             scan_date],
        ["Scan Type",             scan_type],
        ["Tools Used",            scanner],
        ["Total Vulnerabilities", str(total_vulns)],
        ["Critical / High",       str(critical_cnt)],
        ["Open Ports",            port_str],
    ]
    t_scan = Table(scan_table_data, colWidths=[170, 300])
    t_scan.setStyle(_plain_table_style(header_row=True))
    elements.append(t_scan)

    # -- Technologies --
    if tech_list:
        elements.append(Paragraph("Technologies Detected", style_h2))
        elements.append(hr())

        tech_cve_map: dict[str, set] = {}
        for v in vulns:
            if v["CVEs"] != "N/A":
                for te in tech_list:
                    tn = te["Technology"].lower()
                    if tn in v["Type"].lower() or tn in v["Description"].lower():
                        tech_cve_map.setdefault(te["Technology"], set()).update(
                            c.strip() for c in v["CVEs"].split(",")
                        )

        tech_table_data = [["Technology", "Version", "Known CVEs"]]
        for entry in tech_list:
            cves = ", ".join(sorted(tech_cve_map.get(entry["Technology"], set()))) or "None"
            tech_table_data.append([
                Paragraph(entry["Technology"], style_cell),
                Paragraph(entry["Version"],    style_cell),
                Paragraph(cves,                style_cell),
            ])

        t_tech = Table(tech_table_data, colWidths=[160, 90, 220])
        t_tech.setStyle(_plain_table_style(header_row=True))
        elements.append(t_tech)

    # -- Vulnerabilities --
    elements.append(Paragraph("Vulnerabilities", style_h2))
    elements.append(hr())

    if vulns:
        elements.append(Paragraph(
            f"{len(vulns)} issue(s) detected across all scanners, sorted by severity.",
            style_body,
        ))
        elements.append(Spacer(1, 6))

        vuln_table_data = [["Issue", "Severity", "Confidence", "Tool", "URL"]]
        for v in vulns:
            endpoint_display = v["Endpoint"]
            if len(endpoint_display) > 55:
                endpoint_display = endpoint_display[:52] + "..."
            vuln_table_data.append([
                Paragraph(v["Type"],        style_cell),
                Paragraph(v["Severity"],    style_cell),
                Paragraph(v["Confidence"],  style_cell),
                Paragraph(v["Scanner"],     style_cell),
                Paragraph(endpoint_display, style_cell),
            ])

        t_vuln = Table(vuln_table_data, colWidths=[130, 48, 60, 70, 162])
        vuln_style = _plain_table_style(header_row=True)
        for i, v in enumerate(vulns, start=1):
            sev_color = _severity_color(v["Severity"])
            vuln_style.add("TEXTCOLOR", (1, i), (1, i), sev_color)
            vuln_style.add("FONTNAME",  (1, i), (1, i), "Helvetica-Bold")
        t_vuln.setStyle(vuln_style)
        elements.append(t_vuln)
    else:
        elements.append(Paragraph("No vulnerabilities were found.", style_body))

    # -- Crawled URLs --
    elements.append(Paragraph("Crawled URLs", style_h2))
    elements.append(hr())

    if crawled_urls:
        elements.append(Paragraph(
            f"{len(crawled_urls)} endpoint(s) discovered during the crawl phase.",
            style_body,
        ))
        elements.append(Spacer(1, 6))

        # Two-column layout to save vertical space
        url_rows = [["URL", "URL"]]
        it = iter(crawled_urls)
        for left in it:
            right = next(it, "")
            url_rows.append([
                Paragraph(left,  style_url),
                Paragraph(right, style_url),
            ])

        t_urls = Table(url_rows, colWidths=[235, 235])
        t_urls.setStyle(_plain_table_style(header_row=True))
        elements.append(t_urls)
    else:
        elements.append(Paragraph(
            "No crawled URLs recorded for this scan.", style_body
        ))

    # -- SSL / TLS --
    elements.append(Paragraph("SSL / TLS Findings", style_h2))
    elements.append(hr())

    if ssl_findings:
        highest      = ssl_summary.get("highest_severity", "")
        finding_count = ssl_summary.get("finding_count", len(ssl_findings))
        if highest:
            elements.append(Paragraph(
                f"{finding_count} finding(s) — highest severity: <b>{highest}</b>",
                style_body,
            ))
            elements.append(Spacer(1, 6))

        ssl_table_data = [["Severity", "Title", "Description"]]
        for f in ssl_findings:
            desc = f["Description"]
            if len(desc) > 120:
                desc = desc[:117] + "..."
            ssl_table_data.append([
                Paragraph(f["Severity"], style_cell),
                Paragraph(f["Title"],    style_cell),
                Paragraph(desc,          style_cell),
            ])

        t_ssl = Table(ssl_table_data, colWidths=[55, 160, 255])
        ssl_style = _plain_table_style(header_row=True)
        for i, f in enumerate(ssl_findings, start=1):
            sev_label = SEVERITY_LABEL.get(f["Severity"], f["Severity"])
            ssl_style.add("TEXTCOLOR", (0, i), (0, i), _severity_color(sev_label))
            ssl_style.add("FONTNAME",  (0, i), (0, i), "Helvetica-Bold")
        t_ssl.setStyle(ssl_style)
        elements.append(t_ssl)
    else:
        elements.append(Paragraph(
            "No SSL/TLS data available for this scan.", style_body
        ))

    # -- Disclaimer --
    elements.append(Spacer(1, 30))
    elements.append(hr())
    elements.append(Paragraph(
        "Auto-generated by Restack. Results are for reference only. "
        "Always verify findings with a qualified professional.",
        style_disclaimer,
    ))

    # ------------------------------------------------------------------
    # 4. Build
    # ------------------------------------------------------------------
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=inch,
        leftMargin=inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )
    doc.build(elements, onFirstPage=_footer_only, onLaterPages=_footer_only)

    return {"message": "PDF report generated successfully", "path": output_path}