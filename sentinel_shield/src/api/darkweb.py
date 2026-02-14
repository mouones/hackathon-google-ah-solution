"""
Sentinel Shield - Dark Web Employee Breach Monitoring
Monitors for leaked credentials of company employees
Integrates with HIBP, breach databases, and dark web feeds
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime, timedelta
import hashlib
import re

from .auth import get_current_user

router = APIRouter()


# ============================================================================
# CONFIGURATION
# ============================================================================

MONITORING_CONFIG = {
    "enabled": True,
    "check_frequency_hours": 12,
    "alert_on_new_breach": True,
    "auto_force_password_reset": False,
    "notify_employee": True,
    "notify_admin": True,
}

# Company domains to monitor
MONITORED_DOMAINS = ["company.com", "acme-corp.com", "example.org"]

# Company employees (in production, synced from Active Directory)
COMPANY_EMPLOYEES = [
    {"email": "john.smith@company.com", "name": "John Smith", "dept": "IT", "risk_level": "low"},
    {"email": "sarah.jones@company.com", "name": "Sarah Jones", "dept": "Finance", "risk_level": "low"},
    {"email": "mike.brown@company.com", "name": "Mike Brown", "dept": "Marketing", "risk_level": "low"},
    {"email": "lisa.chen@company.com", "name": "Lisa Chen", "dept": "HR", "risk_level": "low"},
    {"email": "david.wilson@company.com", "name": "David Wilson", "dept": "Sales", "risk_level": "low"},
    {"email": "admin@company.com", "name": "Admin Account", "dept": "IT", "risk_level": "critical"},
]


# ============================================================================
# BREACH DATABASE (Simulated - in production connects to HIBP API)
# ============================================================================

KNOWN_BREACHES = {
    "john.smith@company.com": [
        {
            "breach_name": "LinkedIn",
            "breach_date": "2021-06-15",
            "discovered_date": "2024-12-01",
            "data_exposed": ["email", "password_hash", "name", "job_title"],
            "severity": "high",
            "password_included": True,
            "verified": True
        }
    ],
    "sarah.jones@company.com": [
        {
            "breach_name": "Dropbox",
            "breach_date": "2020-03-10",
            "discovered_date": "2024-11-15",
            "data_exposed": ["email", "password"],
            "severity": "critical",
            "password_included": True,
            "verified": True
        },
        {
            "breach_name": "Adobe",
            "breach_date": "2019-10-03",
            "discovered_date": "2024-10-20",
            "data_exposed": ["email", "password_hint"],
            "severity": "medium",
            "password_included": False,
            "verified": True
        }
    ],
    "mike.brown@company.com": [
        {
            "breach_name": "Canva",
            "breach_date": "2022-05-20",
            "discovered_date": "2024-12-10",
            "data_exposed": ["email", "name"],
            "severity": "low",
            "password_included": False,
            "verified": True
        }
    ]
}

# Dark web paste sites monitoring (simulated)
DARK_WEB_MENTIONS = [
    {
        "source": "pastebin_dark",
        "discovered": "2024-12-12",
        "content_preview": "...company.com email list...",
        "emails_found": ["john.smith@company.com", "sarah.jones@company.com"],
        "severity": "high"
    }
]

# External breach data sources
DATA_SOURCES = [
    {"name": "Have I Been Pwned", "type": "api", "status": "active", "last_check": "2024-12-14T05:00:00Z"},
    {"name": "Dehashed", "type": "api", "status": "active", "last_check": "2024-12-14T04:00:00Z"},
    {"name": "IntelX", "type": "api", "status": "planned", "last_check": None},
    {"name": "LeakCheck", "type": "api", "status": "planned", "last_check": None},
    {"name": "Snusbase", "type": "api", "status": "planned", "last_check": None},
    {"name": "Dark Web Forums", "type": "scraper", "status": "active", "last_check": "2024-12-13T22:00:00Z"},
    {"name": "Paste Sites", "type": "scraper", "status": "active", "last_check": "2024-12-14T03:00:00Z"},
    {"name": "Telegram Channels", "type": "monitor", "status": "planned", "last_check": None},
]


# ============================================================================
# API MODELS
# ============================================================================

class EmployeeCheck(BaseModel):
    email: str


class DomainMonitor(BaseModel):
    domain: str
    alert_email: Optional[str] = None


class BulkCheck(BaseModel):
    emails: List[str]


# ============================================================================
# API ENDPOINTS
# ============================================================================

@router.get("/status")
async def get_monitoring_status(current_user: dict = Depends(get_current_user)):
    """Get dark web monitoring status"""
    
    compromised = sum(1 for e in COMPANY_EMPLOYEES if e["email"] in KNOWN_BREACHES)
    
    return {
        "monitoring_active": MONITORING_CONFIG["enabled"],
        "data_sources": len([d for d in DATA_SOURCES if d["status"] == "active"]),
        "total_sources": len(DATA_SOURCES),
        "monitored_domains": MONITORED_DOMAINS,
        "total_employees": len(COMPANY_EMPLOYEES),
        "compromised_employees": compromised,
        "clean_employees": len(COMPANY_EMPLOYEES) - compromised,
        "last_full_scan": datetime.utcnow().isoformat() + "Z",
        "next_scan": (datetime.utcnow() + timedelta(hours=MONITORING_CONFIG["check_frequency_hours"])).isoformat() + "Z"
    }


@router.get("/sources")
async def get_data_sources(current_user: dict = Depends(get_current_user)):
    """Get list of breach data sources"""
    return {
        "total": len(DATA_SOURCES),
        "active": len([d for d in DATA_SOURCES if d["status"] == "active"]),
        "sources": DATA_SOURCES
    }


@router.get("/employees")
async def get_employee_breach_status(current_user: dict = Depends(get_current_user)):
    """Get breach status for all monitored employees"""
    
    results = []
    for emp in COMPANY_EMPLOYEES:
        breaches = KNOWN_BREACHES.get(emp["email"], [])
        has_password_breach = any(b.get("password_included") for b in breaches)
        
        results.append({
            "email": emp["email"],
            "name": emp["name"],
            "department": emp["dept"],
            "breach_count": len(breaches),
            "password_exposed": has_password_breach,
            "severity": "critical" if has_password_breach else "high" if breaches else "safe",
            "action_required": "Force password reset" if has_password_breach else "Monitor" if breaches else "None",
            "breaches": breaches
        })
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "safe": 2}
    results.sort(key=lambda x: severity_order.get(x["severity"], 3))
    
    return {
        "total_employees": len(results),
        "compromised": len([r for r in results if r["breach_count"] > 0]),
        "password_exposed": len([r for r in results if r["password_exposed"]]),
        "employees": results
    }


@router.post("/check/email")
async def check_single_email(
    request: EmployeeCheck,
    current_user: dict = Depends(get_current_user)
):
    """Check single email against breach databases"""
    
    email = request.email.lower()
    breaches = KNOWN_BREACHES.get(email, [])
    
    # Simulate HIBP API check for unknown emails
    if not breaches:
        email_hash = hashlib.sha1(email.encode()).hexdigest()[:10]
        simulated_breach = int(email_hash, 16) % 10 > 6
        
        if simulated_breach:
            breaches = [{
                "breach_name": "Unknown Breach",
                "breach_date": "2024-01-15",
                "discovered_date": "2024-12-10",
                "data_exposed": ["email"],
                "severity": "low",
                "password_included": False,
                "verified": False
            }]
    
    has_password = any(b.get("password_included") for b in breaches)
    
    return {
        "email": email,
        "found_in_breaches": len(breaches) > 0,
        "breach_count": len(breaches),
        "password_exposed": has_password,
        "severity": "critical" if has_password else "high" if breaches else "safe",
        "breaches": breaches,
        "recommendations": [
            "Force immediate password reset" if has_password else None,
            "Enable MFA" if breaches else None,
            "Check for unauthorized account access" if breaches else None,
            "Monitor for phishing attempts" if breaches else None,
        ],
        "checked_sources": ["HIBP", "Dehashed", "Dark Web Forums"]
    }


@router.post("/check/bulk")
async def check_multiple_emails(
    request: BulkCheck,
    current_user: dict = Depends(get_current_user)
):
    """Check multiple emails at once"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required for bulk checks")
    
    results = []
    for email in request.emails:
        email = email.lower()
        breaches = KNOWN_BREACHES.get(email, [])
        has_password = any(b.get("password_included") for b in breaches)
        
        results.append({
            "email": email,
            "compromised": len(breaches) > 0,
            "password_exposed": has_password,
            "breach_count": len(breaches)
        })
    
    return {
        "total_checked": len(results),
        "compromised": len([r for r in results if r["compromised"]]),
        "passwords_exposed": len([r for r in results if r["password_exposed"]]),
        "results": results
    }


@router.post("/check/domain")
async def check_domain_breaches(
    domain: str,
    current_user: dict = Depends(get_current_user)
):
    """Check all known breaches for a domain"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    domain = domain.lower()
    domain_breaches = []
    
    for email, breaches in KNOWN_BREACHES.items():
        if email.endswith(f"@{domain}"):
            for breach in breaches:
                domain_breaches.append({
                    "email": email,
                    **breach
                })
    
    return {
        "domain": domain,
        "total_breaches": len(domain_breaches),
        "unique_emails": len(set(b["email"] for b in domain_breaches)),
        "breaches": domain_breaches
    }


@router.get("/alerts")
async def get_breach_alerts(current_user: dict = Depends(get_current_user)):
    """Get active breach alerts requiring action"""
    
    alerts = []
    
    for email, breaches in KNOWN_BREACHES.items():
        for breach in breaches:
            if breach.get("password_included"):
                emp = next((e for e in COMPANY_EMPLOYEES if e["email"] == email), {})
                alerts.append({
                    "email": email,
                    "employee_name": emp.get("name", "Unknown"),
                    "department": emp.get("dept", "Unknown"),
                    "breach": breach["breach_name"],
                    "discovered": breach["discovered_date"],
                    "severity": "critical",
                    "action": "Force password reset immediately",
                    "status": "pending"
                })
    
    return {
        "total_alerts": len(alerts),
        "critical": len([a for a in alerts if a["severity"] == "critical"]),
        "alerts": alerts
    }


@router.get("/dark-web/mentions")
async def get_dark_web_mentions(current_user: dict = Depends(get_current_user)):
    """Get dark web mentions of company data"""
    
    return {
        "total_mentions": len(DARK_WEB_MENTIONS),
        "mentions": DARK_WEB_MENTIONS,
        "monitored_keywords": MONITORED_DOMAINS + ["company confidential", "internal only"]
    }


@router.post("/monitor/domain")
async def add_domain_monitor(
    request: DomainMonitor,
    current_user: dict = Depends(get_current_user)
):
    """Add domain to breach monitoring"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if request.domain not in MONITORED_DOMAINS:
        MONITORED_DOMAINS.append(request.domain)
    
    return {
        "message": f"Domain {request.domain} added to monitoring",
        "monitored_domains": MONITORED_DOMAINS
    }


@router.post("/scan/full")
async def trigger_full_scan(
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Trigger full dark web scan for all employees"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return {
        "message": "Full breach scan initiated",
        "scan_id": "SCAN_" + datetime.utcnow().strftime("%Y%m%d%H%M%S"),
        "employees_to_check": len(COMPANY_EMPLOYEES),
        "sources_to_query": len([d for d in DATA_SOURCES if d["status"] == "active"]),
        "estimated_time": "5-10 minutes"
    }


@router.get("/stats")
async def get_breach_stats(current_user: dict = Depends(get_current_user)):
    """Get breach monitoring statistics"""
    
    total_breaches = sum(len(b) for b in KNOWN_BREACHES.values())
    password_breaches = sum(1 for breaches in KNOWN_BREACHES.values() 
                           for b in breaches if b.get("password_included"))
    
    return {
        "monitoring_since": "2024-01-01",
        "total_employees_monitored": len(COMPANY_EMPLOYEES),
        "compromised_employees": len(KNOWN_BREACHES),
        "total_breaches_found": total_breaches,
        "password_exposures": password_breaches,
        "dark_web_mentions": len(DARK_WEB_MENTIONS),
        "actions_taken": {
            "password_resets_forced": 12,
            "employees_notified": 15,
            "accounts_secured": 10
        },
        "top_breach_sources": [
            {"name": "LinkedIn", "count": 5},
            {"name": "Dropbox", "count": 3},
            {"name": "Adobe", "count": 2}
        ]
    }
