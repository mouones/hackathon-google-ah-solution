"""
Sentinel Shield - Link Analysis API Routes
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict
from datetime import datetime
import uuid

# Import auth dependency
from .auth import get_current_user

# Import analysis modules
import sys
sys.path.append('..')
from modules.link_analyzer import LinkSecurityAnalyzer

router = APIRouter()

# Initialize analyzer
link_analyzer = LinkSecurityAnalyzer()


# Pydantic Models
class LinkAnalysisRequest(BaseModel):
    url: str
    check_redirects: bool = False
    check_virustotal: bool = False


class BulkLinkRequest(BaseModel):
    urls: List[str]


class URLIndicatorResponse(BaseModel):
    indicator_type: str
    severity: str
    description: str
    score: int


class DomainInfoResponse(BaseModel):
    domain: str
    tld: str
    subdomain_count: int
    has_suspicious_tld: bool
    is_new: Optional[bool] = None
    age_days: Optional[int] = None


class LinkAnalysisResponse(BaseModel):
    analysis_id: str
    url: str
    is_malicious: bool
    threat_score: int
    threat_level: str
    indicators: List[URLIndicatorResponse]
    domain_info: Optional[DomainInfoResponse] = None
    final_url: Optional[str] = None
    redirect_count: int = 0
    virustotal_score: Optional[int] = None
    analyzed_at: datetime


# In-memory storage
analyzed_links: Dict[str, Dict] = {}


@router.post("/analyze", response_model=LinkAnalysisResponse)
async def analyze_link(
    request: LinkAnalysisRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Analyze a URL for security threats
    
    - **url**: URL to analyze
    - **check_redirects**: Follow redirects and analyze chain
    - **check_virustotal**: Query VirusTotal API (requires API key)
    """
    
    analysis_id = str(uuid.uuid4())[:8]
    
    # Perform analysis
    result = link_analyzer.analyze(
        url=request.url,
        check_redirects=request.check_redirects,
        check_virustotal=request.check_virustotal
    )
    
    # Build response
    indicators = [
        URLIndicatorResponse(
            indicator_type=ind.indicator_type,
            severity=ind.severity,
            description=ind.description,
            score=ind.score
        )
        for ind in result.indicators
    ]
    
    domain_info = None
    if result.domain_info:
        domain_info = DomainInfoResponse(
            domain=result.domain_info.domain,
            tld=result.domain_info.tld,
            subdomain_count=result.domain_info.subdomain_count,
            has_suspicious_tld=result.domain_info.has_suspicious_tld,
            is_new=result.domain_info.is_new,
            age_days=result.domain_info.age_days
        )
    
    # Store result
    analyzed_links[analysis_id] = {
        "analysis_id": analysis_id,
        "url": request.url,
        "result": result,
        "user_id": current_user["id"],
        "analyzed_at": datetime.utcnow()
    }
    
    return LinkAnalysisResponse(
        analysis_id=analysis_id,
        url=request.url,
        is_malicious=result.is_malicious,
        threat_score=result.threat_score,
        threat_level=result.threat_level,
        indicators=indicators,
        domain_info=domain_info,
        final_url=result.final_url,
        redirect_count=len(result.redirect_chain) - 1 if result.redirect_chain else 0,
        virustotal_score=result.virustotal_score,
        analyzed_at=datetime.utcnow()
    )


@router.post("/analyze/bulk")
async def analyze_bulk_links(
    request: BulkLinkRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Analyze multiple URLs at once
    
    - **urls**: List of URLs to analyze (max 50)
    """
    
    if len(request.urls) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 URLs per request")
    
    results = []
    for url in request.urls:
        try:
            result = link_analyzer.analyze(url, check_redirects=False, check_virustotal=False)
            results.append({
                "url": url,
                "is_malicious": result.is_malicious,
                "threat_score": result.threat_score,
                "threat_level": result.threat_level
            })
        except Exception as e:
            results.append({
                "url": url,
                "error": str(e),
                "is_malicious": None,
                "threat_score": None
            })
    
    # Summary
    malicious_count = sum(1 for r in results if r.get("is_malicious"))
    
    return {
        "total": len(results),
        "malicious_count": malicious_count,
        "safe_count": len(results) - malicious_count,
        "results": results
    }


@router.post("/extract")
async def extract_and_analyze(
    text: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Extract all URLs from text and analyze them
    """
    
    urls = link_analyzer.extract_urls(text)
    
    if not urls:
        return {
            "total": 0,
            "urls_found": [],
            "message": "No URLs found in text"
        }
    
    results = []
    for url in urls[:20]:  # Limit to 20 URLs
        result = link_analyzer.analyze(url, check_redirects=False)
        results.append({
            "url": url,
            "is_malicious": result.is_malicious,
            "threat_score": result.threat_score,
            "threat_level": result.threat_level,
            "indicators_count": len(result.indicators)
        })
    
    # Calculate overall risk
    max_score = max(r["threat_score"] for r in results) if results else 0
    
    return {
        "total": len(urls),
        "analyzed": len(results),
        "max_threat_score": max_score,
        "overall_risk": "high" if max_score >= 70 else "medium" if max_score >= 40 else "low",
        "results": results
    }


@router.get("/history")
async def get_link_history(
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get link analysis history"""
    
    user_analyses = [
        {
            "analysis_id": a["analysis_id"],
            "url": a["url"],
            "threat_score": a["result"].threat_score,
            "is_malicious": a["result"].is_malicious,
            "analyzed_at": a["analyzed_at"]
        }
        for a in analyzed_links.values()
        if a["user_id"] == current_user["id"]
    ]
    
    # Sort by date descending
    user_analyses.sort(key=lambda x: x["analyzed_at"], reverse=True)
    
    return {
        "total": len(user_analyses),
        "items": user_analyses[:limit]
    }


@router.get("/blocklist")
async def get_blocked_domains(
    current_user: dict = Depends(get_current_user)
):
    """Get list of blocked domains (admin only)"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # In production: fetch from database
    return {
        "domains": [
            {"domain": "evil-phishing.tk", "reason": "Phishing", "blocked_at": datetime.utcnow()},
            {"domain": "malware-download.ga", "reason": "Malware", "blocked_at": datetime.utcnow()},
        ],
        "total": 2
    }


@router.post("/blocklist")
async def add_to_blocklist(
    domain: str,
    reason: str = "Manual block",
    current_user: dict = Depends(get_current_user)
):
    """Add domain to blocklist (admin only)"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # In production: add to database
    
    return {
        "message": f"Domain {domain} added to blocklist",
        "domain": domain,
        "reason": reason
    }
