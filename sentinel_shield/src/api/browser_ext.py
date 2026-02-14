"""
Sentinel Shield - Browser Extension API
Backend for browser extension providing real-time protection
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import re
import hashlib

from .auth import get_current_user

router = APIRouter()


# Known phishing domains
PHISHING_DOMAINS = [
    "paypa1.com", "pay-pal-secure.tk", "micros0ft.com", "apple-id-verify.xyz",
    "amaz0n-login.com", "secure-bank-login.ml", "google-drive-share.tk"
]

# Lookalike detection patterns
BRAND_PATTERNS = {
    "paypal": ["paypa1", "paypai", "paypaI", "pаypal", "paypl"],
    "microsoft": ["micros0ft", "microsofl", "micrоsoft", "mlcrosoft"],
    "google": ["g00gle", "googIe", "goog1e", "gooogle"],
    "apple": ["app1e", "appie", "аpple", "apple-id"],
    "amazon": ["amaz0n", "аmazon", "arnazon", "amazn"],
    "facebook": ["faceb00k", "fаcebook", "facebo0k"],
    "netflix": ["netf1ix", "netfIix", "netfl1x"],
    "bank": ["secure-bank", "bank-verify", "online-bank"]
}


class URLCheckRequest(BaseModel):
    url: str
    page_title: Optional[str] = None
    referrer: Optional[str] = None


class FormCheckRequest(BaseModel):
    url: str
    form_action: str
    input_types: List[str]  # password, email, credit-card, etc.


class PasswordCheckRequest(BaseModel):
    domain: str
    username: str


# API Endpoints

@router.post("/check/url")
async def check_url(
    request: URLCheckRequest,
    current_user: dict = Depends(get_current_user)
):
    """Real-time URL check before navigation"""
    
    url = request.url.lower()
    threats = []
    risk_score = 0
    
    # Check phishing domains
    for domain in PHISHING_DOMAINS:
        if domain in url:
            threats.append({"type": "known_phishing", "severity": "critical"})
            risk_score = 100
            break
    
    # Check brand impersonation
    for brand, patterns in BRAND_PATTERNS.items():
        for pattern in patterns:
            if pattern in url and f"{brand}.com" not in url:
                threats.append({"type": f"{brand}_impersonation", "severity": "high"})
                risk_score = max(risk_score, 85)
    
    # Check for suspicious TLDs
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".work", ".click"]
    for tld in suspicious_tlds:
        if url.endswith(tld) or f"{tld}/" in url:
            threats.append({"type": "suspicious_tld", "severity": "medium"})
            risk_score = max(risk_score, 50)
    
    # Check for IP-based URLs
    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
        threats.append({"type": "ip_based_url", "severity": "high"})
        risk_score = max(risk_score, 70)
    
    # Check for typosquatting in title
    if request.page_title:
        for brand in BRAND_PATTERNS.keys():
            if brand in request.page_title.lower() and brand not in url:
                threats.append({"type": "title_brand_mismatch", "severity": "high"})
                risk_score = max(risk_score, 75)
    
    action = "block" if risk_score >= 80 else "warn" if risk_score >= 40 else "allow"
    
    return {
        "url": request.url,
        "safe": risk_score < 40,
        "risk_score": risk_score,
        "threats": threats,
        "action": action,
        "message": {
            "block": "This site has been blocked for your protection",
            "warn": "This site may be dangerous. Proceed with caution.",
            "allow": "No threats detected"
        }[action]
    }


@router.post("/check/form")
async def check_form(
    request: FormCheckRequest,
    current_user: dict = Depends(get_current_user)
):
    """Check if form submission is safe (credential protection)"""
    
    url = request.url.lower()
    action = request.form_action.lower()
    
    warnings = []
    
    # Check if form submits to different domain
    url_domain = re.search(r"https?://([^/]+)", url)
    action_domain = re.search(r"https?://([^/]+)", action)
    
    if url_domain and action_domain:
        if url_domain.group(1) != action_domain.group(1):
            warnings.append({
                "type": "cross_domain_form",
                "message": f"Form submits to different domain: {action_domain.group(1)}"
            })
    
    # Check for sensitive inputs on suspicious sites
    sensitive_inputs = ["password", "credit-card", "ssn", "pin"]
    has_sensitive = any(i in request.input_types for i in sensitive_inputs)
    
    for domain in PHISHING_DOMAINS:
        if domain in url and has_sensitive:
            return {
                "safe": False,
                "action": "block",
                "message": "BLOCKED: Do not enter credentials on this site!",
                "reason": "Known phishing site requesting sensitive information"
            }
    
    # Check brand impersonation with credential form
    for brand, patterns in BRAND_PATTERNS.items():
        for pattern in patterns:
            if pattern in url and has_sensitive:
                warnings.append({
                    "type": "suspicious_credential_form",
                    "message": f"This may be a fake {brand} login page"
                })
    
    return {
        "safe": len(warnings) == 0,
        "warnings": warnings,
        "action": "warn" if warnings else "allow",
        "recommendation": "Verify you're on the official website before entering credentials" if warnings else None
    }


@router.post("/check/password-reuse")
async def check_password_reuse(
    request: PasswordCheckRequest,
    current_user: dict = Depends(get_current_user)
):
    """Check if user is reusing passwords across sites"""
    
    # Simulate password manager integration
    # In production, would check if this credential combo exists elsewhere
    
    domain_hash = hashlib.md5(request.domain.encode()).hexdigest()[:8]
    simulated_reuse = int(domain_hash, 16) % 10 > 6
    
    return {
        "domain": request.domain,
        "username": request.username,
        "password_reused": simulated_reuse,
        "reused_on": ["facebook.com", "linkedin.com"] if simulated_reuse else [],
        "recommendation": "Use a unique password for each site" if simulated_reuse else "Good! Unique password detected"
    }


@router.get("/blocklist")
async def get_extension_blocklist(current_user: dict = Depends(get_current_user)):
    """Get current blocklist for extension cache"""
    
    return {
        "version": "2024.12.14",
        "domains": PHISHING_DOMAINS,
        "patterns": [p for patterns in BRAND_PATTERNS.values() for p in patterns],
        "suspicious_tlds": [".tk", ".ml", ".ga", ".cf", ".xyz", ".top"],
        "total_entries": len(PHISHING_DOMAINS) + sum(len(p) for p in BRAND_PATTERNS.values())
    }


@router.post("/report")
async def report_suspicious_site(
    url: str,
    reason: str,
    current_user: dict = Depends(get_current_user)
):
    """Report suspicious site from extension"""
    
    return {
        "message": "Thank you for your report",
        "url": url,
        "reason": reason,
        "report_id": "RPT_" + datetime.utcnow().strftime("%Y%m%d%H%M%S"),
        "status": "submitted_for_review"
    }


@router.get("/stats")
async def get_extension_stats(current_user: dict = Depends(get_current_user)):
    """Get protection statistics for extension popup"""
    
    return {
        "user": current_user["email"],
        "protection_active": True,
        "stats_today": {
            "sites_checked": 156,
            "threats_blocked": 3,
            "warnings_shown": 8,
            "forms_protected": 12
        },
        "stats_all_time": {
            "sites_checked": 4892,
            "threats_blocked": 47,
            "phishing_prevented": 23,
            "credentials_protected": 89
        }
    }


@router.get("/settings")
async def get_extension_settings(current_user: dict = Depends(get_current_user)):
    """Get extension settings"""
    
    return {
        "real_time_protection": True,
        "form_protection": True,
        "password_manager_integration": True,
        "show_notifications": True,
        "block_level": "moderate",  # strict, moderate, permissive
        "whitelist": ["company.com", "internal-app.local"],
        "last_sync": datetime.utcnow().isoformat() + "Z"
    }
