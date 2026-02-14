"""
Sentinel Shield - Dashboard API Routes
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime, timedelta
import random

# Import auth dependency
from .auth import get_current_user

router = APIRouter()


# Pydantic Models
class DashboardStats(BaseModel):
    threats_blocked_24h: int
    threats_blocked_7d: int
    threats_blocked_30d: int
    emails_analyzed: int
    links_scanned: int
    active_alerts: int
    quarantined_emails: int
    employee_security_score: float
    malware_detected: int
    phishing_attempts: int


class AlertItem(BaseModel):
    id: str
    type: str
    severity: str
    title: str
    description: str
    timestamp: datetime
    status: str
    source: str


class ThreatBreakdown(BaseModel):
    phishing: int
    malware: int
    spam: int
    suspicious_links: int
    data_exfiltration: int
    other: int


class TimeSeriesPoint(BaseModel):
    timestamp: datetime
    value: int


class AtRiskEmployee(BaseModel):
    name: str
    email: str
    department: str
    security_score: int
    failed_tests: int
    last_incident: Optional[datetime]


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: dict = Depends(get_current_user)
):
    """Get main dashboard statistics"""
    
    return DashboardStats(
        threats_blocked_24h=random.randint(50, 150),
        threats_blocked_7d=random.randint(400, 800),
        threats_blocked_30d=random.randint(1500, 3000),
        emails_analyzed=random.randint(5000, 15000),
        links_scanned=random.randint(2000, 8000),
        active_alerts=random.randint(3, 12),
        quarantined_emails=random.randint(20, 50),
        employee_security_score=round(random.uniform(70, 90), 1),
        malware_detected=random.randint(5, 20),
        phishing_attempts=random.randint(100, 300)
    )


@router.get("/alerts", response_model=List[AlertItem])
async def get_active_alerts(
    severity: Optional[str] = None,
    limit: int = 20,
    current_user: dict = Depends(get_current_user)
):
    """Get active security alerts"""
    
    alerts = [
        AlertItem(
            id="alert_001",
            type="phishing",
            severity="critical",
            title="Brand Impersonation Detected",
            description="Email impersonating Microsoft Security blocked",
            timestamp=datetime.utcnow() - timedelta(minutes=5),
            status="open",
            source="Email Gateway"
        ),
        AlertItem(
            id="alert_002",
            type="malware",
            severity="high",
            title="Malicious Attachment Blocked",
            description="Macro-enabled document detected and quarantined",
            timestamp=datetime.utcnow() - timedelta(minutes=15),
            status="investigating",
            source="Sandbox"
        ),
        AlertItem(
            id="alert_003",
            type="network",
            severity="high",
            title="Suspicious Outbound Traffic",
            description="Unusual data transfer detected from workstation WS-042",
            timestamp=datetime.utcnow() - timedelta(minutes=30),
            status="open",
            source="Network Monitor"
        ),
        AlertItem(
            id="alert_004",
            type="credential",
            severity="medium",
            title="Failed Login Attempts",
            description="5 failed login attempts for admin@company.com",
            timestamp=datetime.utcnow() - timedelta(hours=1),
            status="monitoring",
            source="Auth System"
        ),
        AlertItem(
            id="alert_005",
            type="phishing",
            severity="medium",
            title="Phishing Simulation Failed",
            description="3 employees clicked simulated phishing link",
            timestamp=datetime.utcnow() - timedelta(hours=2),
            status="resolved",
            source="Training Module"
        )
    ]
    
    if severity:
        alerts = [a for a in alerts if a.severity == severity]
    
    return alerts[:limit]


@router.get("/alerts/{alert_id}")
async def get_alert_detail(
    alert_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get detailed alert information"""
    
    return {
        "id": alert_id,
        "type": "phishing",
        "severity": "critical",
        "title": "Brand Impersonation Detected",
        "description": "Email impersonating Microsoft Security blocked",
        "full_details": {
            "sender": "security@rnicrosoft-support.tk",
            "recipient": "user@company.com",
            "subject": "URGENT: Account Suspended",
            "threat_score": 92,
            "indicators": [
                "Homoglyph attack: 'rn' instead of 'm'",
                "Suspicious TLD: .tk",
                "Urgency language detected",
                "Brand impersonation: Microsoft"
            ],
            "automated_actions": [
                "Email quarantined",
                "Sender blocked",
                "Domain added to blocklist"
            ]
        },
        "timeline": [
            {"time": "2024-12-14T03:45:00Z", "action": "Email received"},
            {"time": "2024-12-14T03:45:01Z", "action": "Analysis started"},
            {"time": "2024-12-14T03:45:02Z", "action": "Threat detected (score: 92)"},
            {"time": "2024-12-14T03:45:02Z", "action": "Email quarantined"},
            {"time": "2024-12-14T03:45:03Z", "action": "Alert generated"}
        ],
        "status": "open",
        "assigned_to": None,
        "created_at": datetime.utcnow() - timedelta(minutes=5)
    }


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Acknowledge an alert"""
    
    return {
        "message": "Alert acknowledged",
        "alert_id": alert_id,
        "acknowledged_by": current_user["email"],
        "acknowledged_at": datetime.utcnow()
    }


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    resolution: str = "Confirmed as threat",
    current_user: dict = Depends(get_current_user)
):
    """Resolve an alert"""
    
    return {
        "message": "Alert resolved",
        "alert_id": alert_id,
        "resolution": resolution,
        "resolved_by": current_user["email"],
        "resolved_at": datetime.utcnow()
    }


@router.get("/threats/breakdown", response_model=ThreatBreakdown)
async def get_threat_breakdown(
    period: str = "7d",
    current_user: dict = Depends(get_current_user)
):
    """Get threat breakdown by category"""
    
    return ThreatBreakdown(
        phishing=random.randint(200, 500),
        malware=random.randint(20, 50),
        spam=random.randint(500, 1500),
        suspicious_links=random.randint(100, 300),
        data_exfiltration=random.randint(5, 15),
        other=random.randint(50, 100)
    )


@router.get("/threats/timeline")
async def get_threat_timeline(
    period: str = "24h",
    current_user: dict = Depends(get_current_user)
):
    """Get threat detection timeline"""
    
    now = datetime.utcnow()
    
    if period == "24h":
        points = 24
        delta = timedelta(hours=1)
    elif period == "7d":
        points = 7
        delta = timedelta(days=1)
    else:  # 30d
        points = 30
        delta = timedelta(days=1)
    
    timeline = [
        {
            "timestamp": (now - delta * i).isoformat(),
            "blocked": random.randint(5, 50),
            "allowed": random.randint(100, 500),
            "quarantined": random.randint(0, 10)
        }
        for i in range(points)
    ]
    
    return {
        "period": period,
        "data": list(reversed(timeline))
    }


@router.get("/employees/at-risk", response_model=List[AtRiskEmployee])
async def get_at_risk_employees(
    limit: int = 10,
    current_user: dict = Depends(get_current_user)
):
    """Get employees with lowest security scores"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    employees = [
        AtRiskEmployee(
            name="John Smith",
            email="john.smith@company.com",
            department="Marketing",
            security_score=45,
            failed_tests=3,
            last_incident=datetime.utcnow() - timedelta(days=2)
        ),
        AtRiskEmployee(
            name="Sarah Johnson",
            email="sarah.j@company.com",
            department="Sales",
            security_score=52,
            failed_tests=2,
            last_incident=datetime.utcnow() - timedelta(days=5)
        ),
        AtRiskEmployee(
            name="Mike Williams",
            email="m.williams@company.com",
            department="Finance",
            security_score=58,
            failed_tests=2,
            last_incident=datetime.utcnow() - timedelta(days=7)
        ),
        AtRiskEmployee(
            name="Emily Brown",
            email="emily.b@company.com",
            department="HR",
            security_score=61,
            failed_tests=1,
            last_incident=None
        ),
        AtRiskEmployee(
            name="David Lee",
            email="d.lee@company.com",
            department="Operations",
            security_score=65,
            failed_tests=1,
            last_incident=datetime.utcnow() - timedelta(days=14)
        )
    ]
    
    return employees[:limit]


@router.get("/network/status")
async def get_network_status(
    current_user: dict = Depends(get_current_user)
):
    """Get network security status"""
    
    return {
        "overall_status": "healthy",
        "vlans": [
            {"name": "Corporate", "id": 10, "status": "healthy", "devices": 45},
            {"name": "Marketing", "id": 20, "status": "healthy", "devices": 15},
            {"name": "Sales", "id": 30, "status": "healthy", "devices": 20},
            {"name": "IT", "id": 40, "status": "healthy", "devices": 10},
            {"name": "Guest", "id": 100, "status": "isolated", "devices": 5}
        ],
        "firewall_status": "active",
        "ids_status": "active",
        "last_scan": datetime.utcnow() - timedelta(minutes=5),
        "blocked_connections_1h": random.randint(50, 200),
        "suspicious_connections_1h": random.randint(5, 20)
    }


@router.get("/system/health")
async def get_system_health(
    current_user: dict = Depends(get_current_user)
):
    """Get system health status"""
    
    return {
        "status": "healthy",
        "components": [
            {"name": "Email Gateway", "status": "running", "uptime": "99.9%"},
            {"name": "ML Service", "status": "running", "uptime": "99.8%"},
            {"name": "Link Analyzer", "status": "running", "uptime": "99.9%"},
            {"name": "Sandbox", "status": "running", "uptime": "99.5%"},
            {"name": "Network Monitor", "status": "running", "uptime": "99.9%"},
            {"name": "Database", "status": "running", "uptime": "100%"},
            {"name": "Cache", "status": "running", "uptime": "100%"}
        ],
        "cpu_usage": f"{random.randint(20, 60)}%",
        "memory_usage": f"{random.randint(40, 70)}%",
        "disk_usage": f"{random.randint(30, 50)}%",
        "last_update": datetime.utcnow()
    }
