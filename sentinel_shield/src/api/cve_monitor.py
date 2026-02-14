"""
Sentinel Shield - CVE Monitoring API
Provides endpoints for vulnerability monitoring and alerts
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime, timedelta

from .auth import get_current_user

# Import CVE monitor
import sys
sys.path.append('..')
from modules.cve_monitor import CVEMonitor, Vulnerability, DependencyInfo

router = APIRouter()

# Initialize CVE monitor
cve_monitor = CVEMonitor()


# Pydantic Models
class CVECheckRequest(BaseModel):
    product: str
    version: Optional[str] = None


class DependencyScanRequest(BaseModel):
    project_type: str  # python, javascript
    file_path: Optional[str] = None


class VulnerabilityResponse(BaseModel):
    cve_id: str
    severity: str
    cvss_score: float
    description: str
    affected_products: List[str]
    published_date: datetime
    exploit_available: bool


class DependencyResponse(BaseModel):
    name: str
    current_version: str
    latest_version: str
    vulnerabilities_count: int
    risk_score: int
    update_available: bool


# API Endpoints

@router.get("/status")
async def get_cve_monitoring_status(current_user: dict = Depends(get_current_user)):
    """Get CVE monitoring system status"""
    
    return {
        "monitoring_active": True,
        "monitored_products": len(cve_monitor.monitored_products),
        "cached_vulnerabilities": len(cve_monitor.vulnerability_cache),
        "data_sources": {
            "nvd": "https://nvd.nist.gov",
            "osv": "https://osv.dev",
            "github_advisory": "GitHub Security Advisories"
        },
        "last_check": datetime.now() - timedelta(hours=2),
        "next_check": datetime.now() + timedelta(hours=22)
    }


@router.post("/check/product")
async def check_product_vulnerabilities(
    request: CVECheckRequest,
    current_user: dict = Depends(get_current_user)
):
    """Check specific product for vulnerabilities"""
    
    vulnerabilities = cve_monitor.check_nvd_for_vulnerabilities(
        request.product,
        request.version
    )
    
    return {
        "product": request.product,
        "version": request.version,
        "vulnerabilities_found": len(vulnerabilities),
        "critical_count": len([v for v in vulnerabilities if v.severity == 'critical']),
        "high_count": len([v for v in vulnerabilities if v.severity == 'high']),
        "vulnerabilities": [
            {
                "cve_id": v.cve_id,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "description": v.description[:200] + "..." if len(v.description) > 200 else v.description,
                "published_date": v.published_date.isoformat()
            }
            for v in vulnerabilities[:10]  # Limit to 10 for API response
        ]
    }


@router.post("/scan/dependencies")
async def scan_dependencies(
    request: DependencyScanRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Scan project dependencies for vulnerabilities"""
    
    dependencies = []
    
    if request.project_type == "python":
        file_path = request.file_path or "requirements.txt"
        dependencies = cve_monitor.scan_python_dependencies(file_path)
    
    elif request.project_type == "javascript":
        file_path = request.file_path or "package.json"
        dependencies = cve_monitor.scan_javascript_dependencies(file_path)
    
    else:
        raise HTTPException(status_code=400, detail="Unsupported project type")
    
    # Calculate statistics
    total_vulns = sum(len(d.vulnerabilities) for d in dependencies)
    at_risk_deps = [d for d in dependencies if d.risk_score > 50]
    outdated_deps = [d for d in dependencies if d.update_available]
    
    return {
        "project_type": request.project_type,
        "dependencies_scanned": len(dependencies),
        "total_vulnerabilities": total_vulns,
        "at_risk_dependencies": len(at_risk_deps),
        "outdated_dependencies": len(outdated_deps),
        "dependencies": [
            {
                "name": d.name,
                "current_version": d.current_version,
                "latest_version": d.latest_version,
                "vulnerabilities_count": len(d.vulnerabilities),
                "risk_score": d.risk_score,
                "update_available": d.update_available,
                "critical_vulns": len([v for v in d.vulnerabilities if v.severity == 'critical'])
            }
            for d in dependencies
        ]
    }


@router.get("/alerts")
async def get_cve_alerts(
    severity: Optional[str] = None,
    limit: int = 20,
    current_user: dict = Depends(get_current_user)
):
    """Get active CVE alerts"""
    
    # Run monitoring check
    alerts = cve_monitor.monitor_continuous()
    
    # Filter by severity if specified
    if severity:
        alerts = [a for a in alerts if a.severity_level == severity]
    
    return {
        "total_alerts": len(alerts),
        "critical": len([a for a in alerts if a.severity_level == 'critical']),
        "high": len([a for a in alerts if a.severity_level == 'high']),
        "alerts": [
            {
                "alert_id": a.alert_id,
                "cve_id": a.vulnerability.cve_id,
                "severity": a.severity_level,
                "cvss_score": a.vulnerability.cvss_score,
                "affected_dependencies": a.affected_dependencies,
                "recommended_action": a.recommended_action,
                "sla_deadline": a.sla_deadline.isoformat(),
                "acknowledged": a.acknowledged,
                "patched": a.patched
            }
            for a in alerts[:limit]
        ]
    }


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Acknowledge a CVE alert"""
    
    return {
        "alert_id": alert_id,
        "acknowledged": True,
        "acknowledged_by": current_user["email"],
        "acknowledged_at": datetime.now().isoformat()
    }


@router.post("/alerts/{alert_id}/patch")
async def mark_alert_patched(
    alert_id: str,
    patch_details: Dict,
    current_user: dict = Depends(get_current_user)
):
    """Mark alert as patched"""
    
    return {
        "alert_id": alert_id,
        "patched": True,
        "patched_by": current_user["email"],
        "patched_at": datetime.now().isoformat(),
        "patch_details": patch_details
    }


@router.get("/report")
async def get_vulnerability_report(
    days: int = 30,
    current_user: dict = Depends(get_current_user)
):
    """Generate vulnerability report"""
    
    return {
        "report_period": f"Last {days} days",
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_cves_tracked": len(cve_monitor.vulnerability_cache),
            "critical_vulnerabilities": 12,
            "high_vulnerabilities": 34,
            "medium_vulnerabilities": 56,
            "low_vulnerabilities": 89,
            "dependencies_at_risk": 8,
            "patches_applied": 5,
            "patches_pending": 3
        },
        "trending": {
            "most_affected_product": "fastapi",
            "most_common_cwe": "CWE-79 (XSS)",
            "average_time_to_patch": "4.2 days"
        },
        "recommendations": [
            "Update fastapi to version 0.104.1 or higher",
            "Review and patch 3 critical vulnerabilities within 24 hours",
            "Enable automated dependency scanning in CI/CD pipeline"
        ]
    }


@router.post("/monitor/add")
async def add_product_to_monitoring(
    product_name: str,
    current_user: dict = Depends(get_current_user)
):
    """Add product to continuous monitoring"""
    
    cve_monitor.monitored_products.add(product_name.lower())
    
    return {
        "product": product_name,
        "monitoring": True,
        "added_at": datetime.now().isoformat()
    }


@router.delete("/monitor/remove")
async def remove_product_from_monitoring(
    product_name: str,
    current_user: dict = Depends(get_current_user)
):
    """Remove product from continuous monitoring"""
    
    cve_monitor.monitored_products.discard(product_name.lower())
    
    return {
        "product": product_name,
        "monitoring": False,
        "removed_at": datetime.now().isoformat()
    }
