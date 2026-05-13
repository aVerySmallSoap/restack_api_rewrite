"""
Analytics for vulnerabilities and scanner statistics
"""
from pydantic import AnyUrl
from sqlalchemy import func, case, select, and_
from datetime import datetime, timedelta

from app.modules.database.database import transaction
from app.modules.database.models.findings import VulnerabilityModel
from app.modules.database.models.models import ScanReportModel, Scan, ScanResult


def get_scanner_effectiveness(days: int = 30):
    """Compare Wapiti vs ZAP detection effectiveness"""
    cutoff_date = datetime.now() - timedelta(days=days)

    with transaction() as db:
        # Get scanner statistics
        scanner_stats = db.query(
            VulnerabilityModel.scanner,
            func.count(VulnerabilityModel.id).label('total_detections'),
            func.count(func.distinct(VulnerabilityModel.vulnerability_type)).label('unique_vuln_types'),
            func.avg(
                case(
                    (VulnerabilityModel.severity == 'Critical', 4),
                    (VulnerabilityModel.severity == 'High', 3),
                    (VulnerabilityModel.severity == 'Medium', 2),
                    (VulnerabilityModel.severity == 'Low', 1),
                    else_=0
                )
            ).label('avg_severity_score')
        ).filter(
            VulnerabilityModel.scan_date >= cutoff_date
        ).group_by(VulnerabilityModel.scanner).all()

        comparison = {}
        for scanner, total, unique_types, avg_severity in scanner_stats:
            # Get confidence distribution
            confidence_dist = db.query(
                VulnerabilityModel.confidence,
                func.count(VulnerabilityModel.id).label('count')
            ).filter(
                VulnerabilityModel.scanner == scanner,
                VulnerabilityModel.scan_date >= cutoff_date
            ).group_by(VulnerabilityModel.confidence).all()

            comparison[scanner] = {
                "total_detections": total,
                "unique_vulnerability_types": unique_types,
                "average_severity_score": float(avg_severity) if avg_severity else 0,
                "confidence_distribution": {
                    conf: count for conf, count in confidence_dist
                }
            }

        # Calculate overlap (from scans that used both scanners)
        full_scans = db.query(ScanReportModel).filter(
            ScanReportModel.scanner == 'all',
            ScanReportModel.scan_date >= cutoff_date
        ).all()

        overlap_count = 0
        total_full_scans = len(full_scans)

        for scan in full_scans:
            wapiti_vulns = db.query(VulnerabilityModel.vulnerability_type).filter(
                VulnerabilityModel.scan_id == scan.id,
                VulnerabilityModel.scanner == 'wapiti'
            ).all()

            zap_vulns = db.query(VulnerabilityModel.vulnerability_type).filter(
                VulnerabilityModel.scan_id == scan.id,
                VulnerabilityModel.scanner == 'zap'
            ).all()

            wapiti_types = set([v[0] for v in wapiti_vulns])
            zap_types = set([v[0] for v in zap_vulns])
            overlap_count += len(wapiti_types.intersection(zap_types))

        return {
            "period_days": days,
            "scanner_comparison": comparison,
            "overlap_metrics": {
                "full_scans_analyzed": total_full_scans,
                "average_overlap": overlap_count / total_full_scans if total_full_scans > 0 else 0
            },
            "recommendation": "wapiti" if comparison.get("wapiti", {}).get("total_detections", 0) >
                                            comparison.get("zap", {}).get("total_detections", 0) else "zap"
        }

def get_scan_activity_summary(days: int = 30, target_domain: str = None):
    """
    Overall scanning activity and coverage metrics.
    Optionally filter by target_domain.
    """
    cutoff_date = datetime.now() - timedelta(days=days)

    with transaction() as db:
        # --- Helper to apply target filter ---
        def apply_filter(query, model):
            if not target_domain:
                return query
            if model == Scan:
                return query.filter(Scan.target_url.like(f'%{target_domain}%'))
            if model == ScanReportModel:
                return query.join(Scan, ScanReportModel.scan_id == Scan.id).filter(
                    Scan.target_url.like(f'%{target_domain}%')
                )
            return query

        # 1. Total Scans
        q = db.query(func.count(ScanReportModel.id)).filter(ScanReportModel.scan_date >= cutoff_date)
        total_scans = apply_filter(q, ScanReportModel).scalar() or 0

        # 2. Unique Targets
        q = db.query(func.count(func.distinct(Scan.target_url))).filter(Scan.scan_date >= cutoff_date)
        unique_targets = apply_filter(q, Scan).scalar() or 0

        # 3. Total Vulnerabilities
        q = db.query(func.sum(ScanReportModel.total_vulnerabilities)).filter(ScanReportModel.scan_date >= cutoff_date)
        total_vulns = apply_filter(q, ScanReportModel).scalar() or 0

        # 4. Scan Type Distribution
        q = db.query(ScanReportModel.scan_type, func.count(ScanReportModel.id)).filter(ScanReportModel.scan_date >= cutoff_date)
        scan_types = apply_filter(q, ScanReportModel).group_by(ScanReportModel.scan_type).all()

        # 5. Average Duration
        q = db.query(Scan.scan_type, func.avg(ScanResult.scan_duration)).filter(Scan.scan_date >= cutoff_date)
        avg_durations = apply_filter(q, Scan).group_by(Scan.scan_type).all()

        # 6. Daily Activity
        q = db.query(func.date(ScanReportModel.scan_date).label('date'), func.count(ScanReportModel.id)).filter(ScanReportModel.scan_date >= cutoff_date)
        daily_activity = apply_filter(q, ScanReportModel).group_by('date').order_by('date').all()

        # 7. Top Targets
        q = db.query(Scan.target_url, func.count(Scan.id)).filter(Scan.scan_date >= cutoff_date)
        top_targets = apply_filter(q, Scan).group_by(Scan.target_url).order_by(func.count(Scan.id).desc()).limit(5).all()

        return {
            "period_days": days,
            "filter": target_domain or "all",
            "summary_statistics": {
                "total_scans": total_scans,
                "unique_targets": unique_targets,
                "total_vulnerabilities_found": total_vulns,
                "average_vulns_per_scan": (total_vulns / total_scans) if total_scans > 0 else 0,
                "scans_per_day": round(total_scans / days, 2)
            },
            "scan_type_distribution": {t: c for t, c in scan_types},
            "average_scan_duration": {t: float(d) for t, d in avg_durations},
            "daily_activity": [{"date": str(d), "count": c} for d, c in daily_activity],
            "most_scanned_targets": [{"url": u, "scan_count": c} for u, c in top_targets]
        }

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

def get_top_vulnerable_per_endpoints(report_id: str = None, limit: int = 10):
    """Identify endpoints with the most vulnerabilities"""

    with transaction() as db:
        query = db.query(
            VulnerabilityModel.endpoint,
            func.count(VulnerabilityModel.id).label('vuln_count'),
            func.sum(
                case(
                    (VulnerabilityModel.severity == 'Critical', 1),
                    (VulnerabilityModel.severity == 'High', 1),
                    else_=0
                )
            ).label('critical_high_count')
        )

        if report_id:
            query = query.filter(VulnerabilityModel.scan_id == report_id)

        results = query.group_by(
            VulnerabilityModel.endpoint
        ).order_by(
            func.count(VulnerabilityModel.id).desc()
        ).limit(limit).all()

        endpoint_data = []
        for endpoint, vuln_count, critical_high_count in results:
            # Get severity breakdown for this endpoint
            severity_breakdown = db.query(
                VulnerabilityModel.severity,
                func.count(VulnerabilityModel.id).label('count')
            ).filter(
                VulnerabilityModel.endpoint == endpoint
            )

            if report_id:
                severity_breakdown = severity_breakdown.filter(
                    VulnerabilityModel.scan_id == report_id
                )

            severity_breakdown = severity_breakdown.group_by(
                VulnerabilityModel.severity
            ).all()

            endpoint_data.append({
                "endpoint": endpoint,
                "total_vulnerabilities": vuln_count,
                "critical_high_count": critical_high_count or 0,
                "severity_breakdown": {
                    severity: count for severity, count in severity_breakdown
                },
                "risk_score": (critical_high_count or 0) * 10 + vuln_count
            })

        return {
            "top_vulnerable_endpoints": endpoint_data,
            "total_unique_endpoints": db.query(
                func.count(func.distinct(VulnerabilityModel.endpoint))
            ).scalar()
        }

def get_top_vulnerable_endpoints(report_id: str = None, limit: int = 10):
    """Identify endpoints with the most vulnerabilities"""

    with transaction() as db:
        query = db.query(
            VulnerabilityModel.endpoint,
            func.count(VulnerabilityModel.id).label('vuln_count'),
            func.sum(
                func.case(
                    (VulnerabilityModel.severity == 'Critical', 1),
                    (VulnerabilityModel.severity == 'High', 1),
                    else_=0
                )
            ).label('critical_high_count')
        )

        if report_id:
            query = query.filter(VulnerabilityModel.scan_id == report_id)

        results = query.group_by(
            VulnerabilityModel.endpoint
        ).order_by(
            func.count(VulnerabilityModel.id).desc()
        ).limit(limit).all()

        endpoint_data = []
        for endpoint, vuln_count, critical_high_count in results:
            # Get severity breakdown for this endpoint
            severity_breakdown = db.query(
                VulnerabilityModel.severity,
                func.count(VulnerabilityModel.id).label('count')
            ).filter(
                VulnerabilityModel.endpoint == endpoint
            )

            if report_id:
                severity_breakdown = severity_breakdown.filter(
                    VulnerabilityModel.scan_id == report_id
                )

            severity_breakdown = severity_breakdown.group_by(
                VulnerabilityModel.severity
            ).all()

            endpoint_data.append({
                "endpoint": endpoint,
                "total_vulnerabilities": vuln_count,
                "critical_high_count": critical_high_count or 0,
                "severity_breakdown": {
                    severity: count for severity, count in severity_breakdown
                },
                "risk_score": (critical_high_count or 0) * 10 + vuln_count
            })

        return {
            "top_vulnerable_endpoints": endpoint_data,
            "total_unique_endpoints": db.query(
                func.count(func.distinct(VulnerabilityModel.endpoint))
            ).scalar()
        }

def get_vulnerability_age_distribution(target_url: str = None):
    """Show how long vulnerabilities have been open"""

    with transaction() as db:
        query = db.query(VulnerabilityModel)

        if target_url:
            query = query.join(Scan, VulnerabilityModel.scan_id == Scan.id).filter(
                Scan.target_url == target_url
            )

        vulnerabilities = query.all()

        age_buckets = {
            "0-7_days": [],
            "8-30_days": [],
            "31-90_days": [],
            "91-180_days": [],
            "180+_days": []
        }

        now = datetime.now()
        for vuln in vulnerabilities:
            age_days = (now - vuln.scan_date).days

            vuln_summary = {
                "type": vuln.vulnerability_type,
                "severity": vuln.severity,
                "endpoint": vuln.endpoint,
                "age_days": age_days,
                "first_detected": vuln.scan_date.strftime("%Y-%m-%d")
            }

            if age_days <= 7:
                age_buckets["0-7_days"].append(vuln_summary)
            elif age_days <= 30:
                age_buckets["8-30_days"].append(vuln_summary)
            elif age_days <= 90:
                age_buckets["31-90_days"].append(vuln_summary)
            elif age_days <= 180:
                age_buckets["91-180_days"].append(vuln_summary)
            else:
                age_buckets["180+_days"].append(vuln_summary)

        # Calculate statistics
        total_vulns = len(vulnerabilities)

        return {
            "target_url": target_url or "all_targets",
            "total_vulnerabilities": total_vulns,
            "age_distribution": {
                bucket: {
                    "count": len(vulns),
                    "percentage": (len(vulns) / total_vulns * 100) if total_vulns > 0 else 0,
                    "vulnerabilities": vulns
                }
                for bucket, vulns in age_buckets.items()
            },
            "oldest_vulnerability": max(
                [(now - v.scan_date).days for v in vulnerabilities]
            ) if vulnerabilities else 0,
            "average_age_days": sum(
                [(now - v.scan_date).days for v in vulnerabilities]
            ) / len(vulnerabilities) if vulnerabilities else 0
        }

def get_vulnerability_trend(target_url: str, days: int = 30):
    """Get vulnerability counts over time for a target"""
    with transaction() as db:
        parent_scan = db.query(Scan).filter(Scan.target_url == target_url).all()

        scans = db.query(ScanReportModel).filter(
            ScanReportModel.scan_id == parent_scan.id,
            ScanReportModel.scan_date >= datetime.now() - timedelta(days=days)
        ).order_by(ScanReportModel.scan_date).all()

        return [{
            "date": s.scan_date,
            "total": s.total_vulnerabilities,
            "critical": s.critical_count
        } for s in scans]
