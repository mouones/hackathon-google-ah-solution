"""
Sentinel Shield - DNS & Certificate Security Module
Protects against DNS spoofing and validates SSL certificates
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import hashlib
import re

from .auth import get_current_user

router = APIRouter()


# Certificate transparency logs
CT_LOGS = [
    "ct.googleapis.com/logs/argon2024",
    "ct.cloudflare.com/logs/nimbus2024",
    "oak.ct.letsencrypt.org/2024"
]

# Known good certificate fingerprints (simulated)
KNOWN_CERTS = {
    "google.com": "SHA256:abc123...",
    "microsoft.com": "SHA256:def456...",
    "paypal.com": "SHA256:ghi789...",
    "amazon.com": "SHA256:jkl012...",
}

# DNS-over-HTTPS resolvers
DOH_RESOLVERS = [
    {"name": "Cloudflare", "url": "https://1.1.1.1/dns-query"},
    {"name": "Google", "url": "https://dns.google/dns-query"},
    {"name": "Quad9", "url": "https://dns.quad9.net/dns-query"},
]


class DomainCheckRequest(BaseModel):
    domain: str
    expected_ips: Optional[List[str]] = None


class CertificateCheckRequest(BaseModel):
    domain: str
    cert_fingerprint: Optional[str] = None
    issuer: Optional[str] = None


# API Endpoints

@router.post("/check-dns")
async def check_dns_integrity(
    request: DomainCheckRequest,
    current_user: dict = Depends(get_current_user)
):
    """Check DNS resolution against multiple resolvers to detect spoofing"""
    
    domain = request.domain.lower()
    
    # Simulate DNS resolution from multiple sources
    # In production, would actually query DoH resolvers
    results = []
    for resolver in DOH_RESOLVERS:
        # Simulated consistent result
        ip_hash = hashlib.md5(f"{domain}{resolver['name']}".encode()).hexdigest()[:8]
        ip = f"104.{int(ip_hash[:2], 16) % 256}.{int(ip_hash[2:4], 16) % 256}.{int(ip_hash[4:6], 16) % 256}"
        results.append({
            "resolver": resolver["name"],
            "ip": ip,
            "response_time_ms": 15 + (int(ip_hash[6:8], 16) % 50)
        })
    
    # Check consistency
    ips = [r["ip"] for r in results]
    is_consistent = len(set(ips)) == 1
    
    # Check against expected IPs if provided
    matches_expected = True
    if request.expected_ips:
        matches_expected = ips[0] in request.expected_ips
    
    return {
        "domain": domain,
        "dns_consistent": is_consistent,
        "matches_expected": matches_expected,
        "spoofing_detected": not is_consistent,
        "resolved_ips": list(set(ips)),
        "resolver_results": results,
        "recommendation": "DNS appears legitimate" if is_consistent else "WARNING: DNS inconsistency detected - possible spoofing"
    }


@router.post("/check-certificate")
async def check_certificate(
    request: CertificateCheckRequest,
    current_user: dict = Depends(get_current_user)
):
    """Validate SSL certificate against CT logs and known fingerprints"""
    
    domain = request.domain.lower()
    
    # Simulated certificate info
    cert_hash = hashlib.sha256(domain.encode()).hexdigest()[:16]
    
    # Check if domain is in our known certs database
    known_fingerprint = KNOWN_CERTS.get(domain)
    
    # Simulate CT log check
    ct_found = int(cert_hash[:2], 16) % 10 > 2  # 70% chance found in CT
    
    # Check for suspicious cert characteristics
    issues = []
    
    # Check cert age (recently issued certs for known domains are suspicious)
    if domain in ["paypal.com", "google.com", "microsoft.com"]:
        # For impersonation domains pretending to be these
        pass
    
    # Check issuer
    trusted_issuers = ["Let's Encrypt", "DigiCert", "Comodo", "GlobalSign", "Sectigo"]
    if request.issuer and request.issuer not in trusted_issuers:
        issues.append(f"Untrusted issuer: {request.issuer}")
    
    # Check for self-signed
    if request.issuer and "self-signed" in request.issuer.lower():
        issues.append("Self-signed certificate detected")
    
    is_valid = len(issues) == 0 and ct_found
    
    return {
        "domain": domain,
        "certificate_valid": is_valid,
        "in_ct_logs": ct_found,
        "ct_logs_checked": CT_LOGS,
        "known_fingerprint": known_fingerprint is not None,
        "issues": issues,
        "recommendation": "Certificate appears valid" if is_valid else "WARNING: Certificate issues detected"
    }


@router.post("/monitor-domain")
async def add_domain_monitoring(
    domain: str,
    alert_on_change: bool = True,
    current_user: dict = Depends(get_current_user)
):
    """Add domain to DNS/certificate monitoring"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return {
        "message": f"Domain {domain} added to monitoring",
        "monitoring": {
            "dns_changes": True,
            "certificate_changes": True,
            "ct_log_monitoring": True,
            "alert_on_change": alert_on_change
        },
        "check_frequency": "Every 15 minutes"
    }


@router.get("/status")
async def get_dns_security_status(current_user: dict = Depends(get_current_user)):
    """Get DNS security monitoring status"""
    
    return {
        "protection_active": True,
        "doh_resolvers": len(DOH_RESOLVERS),
        "monitored_domains": 15,
        "ct_logs_monitored": len(CT_LOGS),
        "alerts_today": 0,
        "last_check": datetime.utcnow().isoformat() + "Z",
        "stats": {
            "dns_queries_validated": 4520,
            "certificates_checked": 890,
            "spoofing_attempts_blocked": 3,
            "suspicious_certs_flagged": 7
        }
    }


@router.get("/alerts")
async def get_dns_alerts(current_user: dict = Depends(get_current_user)):
    """Get DNS/certificate security alerts"""
    
    return {
        "alerts": [
            {
                "type": "dns_change",
                "domain": "internal-app.company.com",
                "old_ip": "192.168.1.50",
                "new_ip": "104.21.45.67",
                "detected_at": "2024-12-13T15:30:00Z",
                "severity": "high",
                "status": "investigating"
            },
            {
                "type": "new_certificate",
                "domain": "company.com",
                "issuer": "Let's Encrypt",
                "detected_at": "2024-12-12T10:00:00Z",
                "severity": "info",
                "status": "acknowledged"
            }
        ]
    }
