"""
Sentinel Shield - Threat Intelligence API Routes
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
class IOC(BaseModel):
    id: str
    type: str  # domain, ip, hash, email
    value: str
    threat_type: str  # phishing, malware, c2, spam
    confidence: int  # 0-100
    first_seen: datetime
    last_seen: datetime
    occurrences: int
    source: str


class ThreatFeed(BaseModel):
    name: str
    type: str
    url: str
    last_update: datetime
    ioc_count: int
    status: str


class ThreatStats(BaseModel):
    total_iocs: int
    new_iocs_24h: int
    phishing_domains: int
    malware_hashes: int
    blocked_ips: int
    active_feeds: int


# Sample threat intelligence data
threat_feeds = [
    {
        "name": "URLhaus Malware URLs",
        "type": "url",
        "url": "https://urlhaus.abuse.ch",
        "last_update": datetime.utcnow() - timedelta(hours=1),
        "ioc_count": 125000,
        "status": "active"
    },
    {
        "name": "PhishTank Database",
        "type": "url",
        "url": "https://phishtank.org",
        "last_update": datetime.utcnow() - timedelta(hours=2),
        "ioc_count": 75000,
        "status": "active"
    },
    {
        "name": "AlienVault OTX",
        "type": "mixed",
        "url": "https://otx.alienvault.com",
        "last_update": datetime.utcnow() - timedelta(hours=4),
        "ioc_count": 500000,
        "status": "active"
    },
    {
        "name": "Abuse.ch Feodo Tracker",
        "type": "ip",
        "url": "https://feodotracker.abuse.ch",
        "last_update": datetime.utcnow() - timedelta(hours=1),
        "ioc_count": 2500,
        "status": "active"
    },
    {
        "name": "MalwareBazaar",
        "type": "hash",
        "url": "https://bazaar.abuse.ch",
        "last_update": datetime.utcnow() - timedelta(hours=6),
        "ioc_count": 450000,
        "status": "active"
    }
]

# Sample IOCs
sample_iocs: List[Dict] = [
    {
        "id": "ioc_001",
        "type": "domain",
        "value": "evil-phishing-site.tk",
        "threat_type": "phishing",
        "confidence": 95,
        "first_seen": datetime.utcnow() - timedelta(days=5),
        "last_seen": datetime.utcnow() - timedelta(hours=2),
        "occurrences": 150,
        "source": "Internal Detection"
    },
    {
        "id": "ioc_002",
        "type": "ip",
        "value": "185.234.72.45",
        "threat_type": "c2",
        "confidence": 90,
        "first_seen": datetime.utcnow() - timedelta(days=10),
        "last_seen": datetime.utcnow() - timedelta(hours=12),
        "occurrences": 45,
        "source": "Feodo Tracker"
    },
    {
        "id": "ioc_003",
        "type": "hash",
        "value": "a1b2c3d4e5f6789012345678abcdef01",
        "threat_type": "malware",
        "confidence": 100,
        "first_seen": datetime.utcnow() - timedelta(days=3),
        "last_seen": datetime.utcnow() - timedelta(hours=1),
        "occurrences": 25,
        "source": "MalwareBazaar"
    },
    {
        "id": "ioc_004",
        "type": "email",
        "value": "scammer@fake-microsoft.tk",
        "threat_type": "phishing",
        "confidence": 98,
        "first_seen": datetime.utcnow() - timedelta(days=1),
        "last_seen": datetime.utcnow() - timedelta(minutes=30),
        "occurrences": 500,
        "source": "Internal Detection"
    }
]


@router.get("/stats", response_model=ThreatStats)
async def get_threat_stats(
    current_user: dict = Depends(get_current_user)
):
    """Get threat intelligence statistics"""
    
    return ThreatStats(
        total_iocs=sum(f["ioc_count"] for f in threat_feeds),
        new_iocs_24h=random.randint(500, 2000),
        phishing_domains=75000,
        malware_hashes=450000,
        blocked_ips=2500,
        active_feeds=len([f for f in threat_feeds if f["status"] == "active"])
    )


@router.get("/feeds", response_model=List[ThreatFeed])
async def list_threat_feeds(
    current_user: dict = Depends(get_current_user)
):
    """List configured threat intelligence feeds"""
    
    return [ThreatFeed(**f) for f in threat_feeds]


@router.get("/iocs")
async def list_iocs(
    type: Optional[str] = None,
    threat_type: Optional[str] = None,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """
    List indicators of compromise
    
    - **type**: Filter by IOC type (domain, ip, hash, email)
    - **threat_type**: Filter by threat type (phishing, malware, c2, spam)
    - **limit**: Maximum results to return
    """
    
    results = sample_iocs.copy()
    
    if type:
        results = [i for i in results if i["type"] == type]
    
    if threat_type:
        results = [i for i in results if i["threat_type"] == threat_type]
    
    return {
        "total": len(results),
        "items": results[:limit]
    }


@router.get("/iocs/{ioc_id}", response_model=IOC)
async def get_ioc_detail(
    ioc_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get detailed information about an IOC"""
    
    ioc = next((i for i in sample_iocs if i["id"] == ioc_id), None)
    
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    
    return IOC(**ioc)


@router.post("/iocs")
async def add_ioc(
    type: str,
    value: str,
    threat_type: str,
    confidence: int = 80,
    current_user: dict = Depends(get_current_user)
):
    """Add a new indicator of compromise (admin only)"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    new_ioc = {
        "id": f"ioc_{len(sample_iocs) + 1:03d}",
        "type": type,
        "value": value,
        "threat_type": threat_type,
        "confidence": confidence,
        "first_seen": datetime.utcnow(),
        "last_seen": datetime.utcnow(),
        "occurrences": 1,
        "source": "Manual Entry"
    }
    
    sample_iocs.append(new_ioc)
    
    return {
        "message": "IOC added successfully",
        "ioc": new_ioc
    }


@router.get("/lookup/{value}")
async def lookup_ioc(
    value: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Search for an IOC value across all intelligence
    
    - **value**: Domain, IP, hash, or email to look up
    """
    
    # Search in internal database
    matches = [i for i in sample_iocs if value.lower() in i["value"].lower()]
    
    # In production: also search external sources
    
    if matches:
        return {
            "found": True,
            "matches": matches,
            "message": f"Found {len(matches)} match(es) in threat intelligence"
        }
    else:
        return {
            "found": False,
            "matches": [],
            "message": "No matches found in threat intelligence"
        }


@router.post("/feeds/sync")
async def sync_threat_feeds(
    current_user: dict = Depends(get_current_user)
):
    """Manually trigger threat feed synchronization (admin only)"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # In production: trigger actual feed sync
    
    return {
        "message": "Threat feed synchronization started",
        "feeds_queued": len(threat_feeds),
        "estimated_time": "5-10 minutes"
    }


@router.get("/hunting")
async def threat_hunting_queries(
    current_user: dict = Depends(get_current_user)
):
    """Get automated threat hunting results"""
    
    # Sample hunting queries and results
    hunting_results = [
        {
            "query": "Emails from newly registered domains (<7 days)",
            "matches": 12,
            "severity": "high",
            "last_run": datetime.utcnow() - timedelta(hours=1)
        },
        {
            "query": "Outbound connections to known C2 IPs",
            "matches": 0,
            "severity": "critical",
            "last_run": datetime.utcnow() - timedelta(minutes=15)
        },
        {
            "query": "Encoded PowerShell commands",
            "matches": 3,
            "severity": "high",
            "last_run": datetime.utcnow() - timedelta(hours=2)
        },
        {
            "query": "Large data transfers after hours",
            "matches": 5,
            "severity": "medium",
            "last_run": datetime.utcnow() - timedelta(hours=4)
        }
    ]
    
    return {
        "total_queries": len(hunting_results),
        "total_matches": sum(h["matches"] for h in hunting_results),
        "results": hunting_results
    }
