from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import numpy as np
import pandas as pd
import math
from pydantic import AnyUrl
from sqlalchemy import select, and_, func, desc

from app.modules.database.database import transaction
from app.modules.database.models.models import ScanReportModel, Scan
from app.modules.database.models.findings import VulnerabilityModel



def calculate_time_series(target_url: AnyUrl, days: int = 90, start_date: str = None, end_date: str = None):
    """
    Generates time-series data. Supports explicit date range or 'last N days'.
    """
    domain_str = target_url.host if target_url.host else str(target_url)

    with transaction() as db:
        # Base query: Join Report and Scan, filter by domain
        stmt = (
            select(ScanReportModel)
            .join(Scan, ScanReportModel.scan_id == Scan.id)
            .where(Scan.target_url.ilike(f"%{domain_str}%"))
        )

        # Apply Date Filter
        if start_date and end_date:
            # Parse ISO strings (YYYY-MM-DD) passed from frontend
            s_date = datetime.strptime(start_date, "%Y-%m-%d")
            # Add one day to end_date to include the full day (since timestamps have time)
            e_date = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)

            stmt = stmt.where(and_(ScanReportModel.scan_date >= s_date, ScanReportModel.scan_date < e_date))
        else:
            # Fallback to simple 'days ago' logic
            cutoff_date = datetime.now() - timedelta(days=days)
            stmt = stmt.where(ScanReportModel.scan_date >= cutoff_date)

        # Finalize order
        stmt = stmt.order_by(ScanReportModel.scan_date)

        scans = db.scalars(stmt).all()

        timeseries_data = []

        for scan in scans:
            timeseries_data.append({
                "date": scan.scan_date.strftime("%Y-%m-%d %H:%M"),
                "count": scan.total_vulnerabilities,
                "critical_count": scan.critical_count,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "scan_type": scan.scan_type
            })

    return timeseries_data

#noinspection D
def get_general_analytics(
        target_domain: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        user_id: Optional[int] = None  # <--- Ensure this is typed
) -> Dict[str, Any]:
    """
    Standardized Analytics Endpoint for Visualizations.
    Aggregates vulnerabilities by date (one point per day), filtered by User.
    """

    with transaction() as db:
        # 1. DATE FILTER LOGIC
        if start_date and end_date:
            try:
                s_date = datetime.strptime(start_date, "%Y-%m-%d")
                e_date = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
                cutoff_filter = and_(ScanReportModel.scan_date >= s_date, ScanReportModel.scan_date < e_date)
                days_analyzed = (datetime.strptime(end_date, "%Y-%m-%d") - s_date).days
            except ValueError:
                return {"error": "Invalid date format. Use YYYY-MM-DD"}
        else:
            # Default 30 Days
            days_analyzed = 30
            cutoff_date = datetime.now() - timedelta(days=30)
            cutoff_filter = ScanReportModel.scan_date >= cutoff_date

        # 2. FETCH HISTORY WITH DAILY AGGREGATION
        # Group by date and sum vulnerabilities found that day
        stmt = (
            select(
                func.date(ScanReportModel.scan_date).label('scan_date'),
                func.sum(ScanReportModel.total_vulnerabilities).label('total_vulns'),
                func.sum(ScanReportModel.critical_count).label('critical_vulns')
            )
            .join(Scan, ScanReportModel.scan_id == Scan.id)
            .where(cutoff_filter)
        )

        # --- APPLY USER FILTER ---
        if user_id is not None:
            stmt = stmt.where(Scan.user_id == user_id) # TODO: add users

        if target_domain and target_domain != 'all':
            stmt = stmt.where(Scan.target_url.ilike(f"%{target_domain}%"))

        stmt = stmt.group_by(func.date(ScanReportModel.scan_date)).order_by(func.date(ScanReportModel.scan_date))

        # Execute aggregated query
        daily_results = db.execute(stmt).all()

        # Handle empty data gracefully
        if not daily_results:
            return {
                "kpi": {
                    "target": target_domain if target_domain else "All Targets",
                    "total_scans": 0,
                    "total_vulns": 0,
                    "total_vulns_all_time": 0,
                    "days_analyzed": days_analyzed,
                    "stability_score": 0,
                    "last_scan": None
                },
                "charts": {
                    "history": [],
                    "distribution": [],
                    "types": [],
                    "trend": []
                }
            }

        # 3. PREPARE HISTORY DATA (aggregated by date)
        history_data = []
        for row in daily_results:
            history_data.append({
                "date": row.scan_date.strftime("%Y-%m-%d"),
                "timestamp": datetime.combine(row.scan_date, datetime.min.time()).timestamp(),
                "Total": int(row.total_vulns or 0),
                "Critical": int(row.critical_vulns or 0)
            })

        df = pd.DataFrame(history_data)

        # 4. GET ALL REPORTS IN TIME RANGE FOR ACCURATE COUNTS
        # Fetch all reports for the current filter to get accurate scan count and aggregated stats
        all_reports_stmt = (
            select(ScanReportModel)
            .join(Scan, ScanReportModel.scan_id == Scan.id)
            .where(cutoff_filter)
        )

        # --- APPLY USER FILTER ---
        if user_id is not None:
            all_reports_stmt = all_reports_stmt.where(Scan.user_id == user_id)

        if target_domain and target_domain != 'all':
            all_reports_stmt = all_reports_stmt.where(Scan.target_url.ilike(f"%{target_domain}%"))

        all_reports_stmt = all_reports_stmt.order_by(desc(ScanReportModel.scan_date))
        all_reports = db.scalars(all_reports_stmt).all()

        # Get the latest report for "current state" reference
        latest_report = all_reports[0] if all_reports else None

        if not latest_report:
            return {
                "kpi": {
                    "target": target_domain if target_domain else "All Targets",
                    "total_scans": len(all_reports),
                    "total_vulns": int(df['Total'].iloc[-1]) if len(df) > 0 else 0,
                    "total_vulns_all_time": 0,
                    "days_analyzed": days_analyzed,
                    "stability_score": 0,
                    "last_scan": df['date'].iloc[-1] if len(df) > 0 else None
                },
                "charts": {
                    "history": history_data,
                    "distribution": [],
                    "types": [],
                    "trend": []
                }
            }

        # 7. STATISTICAL ANALYSIS (Stability & Trend)
        total_scans = len(daily_results)
        stability_score = 0
        trend_data = []

        if len(df) > 1:
            mean = df['Total'].mean()
            std = df['Total'].std()
            # guard against zero mean before dividing
            cov = (std / mean) if mean > 0 else 0
            stability_score = max(0, int(100 - (_safe_float(cov) * 100)))

            x_vals = np.arange(len(df))
            y_vals = df['Total'].values

            slope, intercept = np.polyfit(x_vals, y_vals, 1)
            df['regression'] = (slope * x_vals) + intercept

            trend_df = df[['date', 'Total', 'regression']].rename(columns={'Total': 'value'})
            trend_data = [
                {
                    'date': row['date'],
                    'value': _safe_float(row['value']),
                    'regression': _safe_float(row['regression']),
                }
                for row in trend_df.to_dict(orient='records')
            ]
        else:
            stability_score = 100
            trend_data = [
                {
                    'date': r['date'],
                    'value': _safe_float(r['Total']),
                    'regression': _safe_float(r['Total']),
                }
                for r in history_data
            ]

        # 6. SNAPSHOT ANALYSIS - AGGREGATED ACROSS ALL REPORTS IN TIME RANGE
        all_scan_ids = [r.scan_id for r in all_reports]

        if not all_scan_ids:
            dist_data = []
            top_types = []
            total_vulns_actual = 0
        else:
            sev_counts = db.query(
                VulnerabilityModel.severity, func.count(VulnerabilityModel.id)
            ).filter(
                VulnerabilityModel.scan_id.in_(all_scan_ids)
            ).group_by(VulnerabilityModel.severity).all()

            sev_map = {s.lower(): c for s, c in sev_counts}
            total_vulns_actual = sum(count for _, count in sev_counts)

            dist_data = [
                {"name": "critical", "value": sev_map.get("critical", 0)},
                {"name": "high", "value": sev_map.get("high", 0) + sev_map.get("error", 0)},
                {"name": "medium", "value": sev_map.get("medium", 0) + sev_map.get("warning", 0)},
                {"name": "low", "value": sev_map.get("low", 0) + sev_map.get("note", 0)},
                {"name": "informational", "value": sev_map.get("informational", 0)}
            ]
            dist_data = [d for d in dist_data if d['value'] > 0]

            # B. Type Distribution
            type_counts = db.query(
                VulnerabilityModel.vulnerability_type,
                VulnerabilityModel.severity,
                func.count(VulnerabilityModel.id)
            ).filter(
                VulnerabilityModel.scan_id.in_(all_scan_ids)
            ).group_by(
                VulnerabilityModel.vulnerability_type, VulnerabilityModel.severity
            ).all()

            type_map = {}
            for v_type, severity, count in type_counts:
                clean_type = v_type.replace('_', ' ').replace('-', ' ').title()

                if clean_type not in type_map:
                    type_map[clean_type] = {"name": clean_type, "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

                s_lower = severity.lower()
                if s_lower == 'error': s_lower = 'high'
                if s_lower == 'warning': s_lower = 'medium'
                if s_lower == 'note': s_lower = 'low'

                if s_lower in type_map[clean_type]:
                    type_map[clean_type][s_lower] += count
                type_map[clean_type]["total"] += count

            top_types = sorted(type_map.values(), key=lambda x: x['total'], reverse=True)[:5]

        return {
            "kpi": {
                "target": target_domain if target_domain else "All Targets",
                "total_scans": total_scans,
                "total_vulns": total_vulns_actual,
                "total_vulns_all_time": sum(r.total_vulnerabilities for r in all_reports),
                "days_analyzed": days_analyzed,
                "stability_score": stability_score,
                "last_scan": latest_report.scan_date.strftime("%Y-%m-%d")
            },
            "charts": {
                "history": history_data,
                "distribution": dist_data,
                "types": top_types,
                "trend": trend_data
            }
        }


def get_raw_vulnerabilities(
        target_domain: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 1000,
        user_id: Optional[int] = None  # <--- Add param
) -> list[dict]:
    """
    Fetches a raw list of vulnerabilities with filters, scoped by User.
    """
    stmt = (
        select(
            VulnerabilityModel.severity,
            VulnerabilityModel.vulnerability_type,
            VulnerabilityModel.endpoint,
            VulnerabilityModel.scanner,
            VulnerabilityModel.scan_date,
            Scan.target_url
        )
        .join(ScanReportModel, VulnerabilityModel.scan_id == ScanReportModel.scan_id)
        .join(Scan, ScanReportModel.scan_id == Scan.id)
        .distinct()
        .order_by(desc(VulnerabilityModel.scan_date))
        .limit(limit)
    )

    filters = []

    with transaction() as db:
        # --- APPLY USER FILTER ---
        if user_id is not None:
            filters.append(Scan.user_id == user_id) # TODO: Add users table

        if start_date and end_date:
            try:
                s_date = datetime.strptime(start_date, "%Y-%m-%d")
                e_date = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
                filters.append(VulnerabilityModel.scan_date >= s_date)
                filters.append(VulnerabilityModel.scan_date < e_date)
            except ValueError:
                pass

        if target_domain and target_domain != 'all':
            filters.append(Scan.target_url.ilike(f"%{target_domain}%"))

        if filters:
            stmt = stmt.where(and_(*filters))

        results = db.execute(stmt).all()

        data = []
        for row in results:
            data.append({
                "severity": row.severity,
                "type": row.vulnerability_type,
                "endpoint": row.endpoint,
                "scanner": row.scanner,
                "date": row.scan_date.strftime("%Y-%m-%d"),
                "target": row.target_url
            })

        return data

def _safe_float(val, default=0.0):
    """Convert nan/inf to a safe default before JSON serialization."""
    try:
        f = float(val)
        return default if (math.isnan(f) or math.isinf(f)) else f
    except (TypeError, ValueError):
        return default