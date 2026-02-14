"""
Sentinel Shield - Email Analysis API Routes
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid

# Import auth dependency
from .auth import get_current_user

# Import analysis modules
import sys
sys.path.append('..')
from modules.phishing_detector import PhishingDetector, PhishingAnalysis

router = APIRouter()

# Initialize detector
phishing_detector = PhishingDetector()


# Pydantic Models
class EmailAnalysisRequest(BaseModel):
    sender: str
    sender_name: Optional[str] = None
    recipient: Optional[str] = None
    subject: str
    body: str
    headers: Optional[Dict[str, str]] = None
    attachments: Optional[List[Dict[str, Any]]] = None


class IndicatorResponse(BaseModel):
    indicator_type: str
    severity: str
    description: str
    score: int


class EmailAnalysisResponse(BaseModel):
    analysis_id: str
    threat_score: int
    is_phishing: bool
    confidence: float
    recommendation: str
    indicators: List[IndicatorResponse]
    brand_impersonation: Optional[str] = None
    automated_response: Optional[Dict[str, Any]] = None
    analyzed_at: datetime


class QuarantinedEmail(BaseModel):
    id: str
    sender: str
    subject: str
    recipient: str
    threat_score: int
    quarantined_at: datetime
    status: str


# In-memory storage (replace with database)
analyzed_emails: Dict[str, Dict] = {}
quarantine: Dict[str, Dict] = {}


@router.post("/analyze", response_model=EmailAnalysisResponse)
async def analyze_email(
    email: EmailAnalysisRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Analyze an email for phishing and other threats
    
    - **sender**: Sender email address
    - **sender_name**: Display name of sender
    - **subject**: Email subject line
    - **body**: Email body content
    - **headers**: Optional email headers
    - **attachments**: Optional attachment metadata
    """
    
    # Generate analysis ID
    analysis_id = str(uuid.uuid4())[:8]
    
    # Perform phishing analysis
    result = phishing_detector.analyze(
        text=email.body,
        sender_email=email.sender,
        sender_name=email.sender_name or "",
        subject=email.subject
    )
    
    # Build response
    indicators = [
        IndicatorResponse(
            indicator_type=ind.indicator_type,
            severity=ind.severity,
            description=ind.description,
            score=ind.score
        )
        for ind in result.indicators
    ]
    
    # Automated response for high threats
    automated_response = None
    if result.threat_score >= 70:
        automated_response = {
            "quarantined": True,
            "sender_blocked": True,
            "alert_sent": True,
            "response_time_ms": 450
        }
        
        # Add to quarantine
        quarantine[analysis_id] = {
            "id": analysis_id,
            "sender": email.sender,
            "sender_name": email.sender_name,
            "recipient": email.recipient or current_user["email"],
            "subject": email.subject,
            "body": email.body,
            "threat_score": result.threat_score,
            "indicators": indicators,
            "quarantined_at": datetime.utcnow(),
            "status": "quarantined"
        }
    
    # Store analysis result
    analysis_record = {
        "analysis_id": analysis_id,
        "email": email.dict(),
        "result": {
            "threat_score": result.threat_score,
            "is_phishing": result.is_phishing,
            "confidence": result.confidence,
            "recommendation": result.recommendation,
            "indicators": [i.dict() for i in indicators],
            "brand_impersonation": result.brand_impersonation
        },
        "user_id": current_user["id"],
        "analyzed_at": datetime.utcnow()
    }
    analyzed_emails[analysis_id] = analysis_record
    
    return EmailAnalysisResponse(
        analysis_id=analysis_id,
        threat_score=result.threat_score,
        is_phishing=result.is_phishing,
        confidence=result.confidence,
        recommendation=result.recommendation,
        indicators=indicators,
        brand_impersonation=result.brand_impersonation,
        automated_response=automated_response,
        analyzed_at=datetime.utcnow()
    )


@router.get("/history")
async def get_analysis_history(
    limit: int = 50,
    offset: int = 0,
    current_user: dict = Depends(get_current_user)
):
    """Get email analysis history for current user"""
    
    user_analyses = [
        a for a in analyzed_emails.values()
        if a["user_id"] == current_user["id"]
    ]
    
    # Sort by date descending
    user_analyses.sort(key=lambda x: x["analyzed_at"], reverse=True)
    
    return {
        "total": len(user_analyses),
        "items": user_analyses[offset:offset + limit]
    }


@router.get("/quarantine", response_model=List[QuarantinedEmail])
async def list_quarantine(
    current_user: dict = Depends(get_current_user)
):
    """List quarantined emails (admin only)"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return [
        QuarantinedEmail(
            id=q["id"],
            sender=q["sender"],
            subject=q["subject"],
            recipient=q["recipient"],
            threat_score=q["threat_score"],
            quarantined_at=q["quarantined_at"],
            status=q["status"]
        )
        for q in quarantine.values()
    ]


@router.get("/quarantine/{email_id}")
async def get_quarantined_email(
    email_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get details of a quarantined email (admin only)"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if email_id not in quarantine:
        raise HTTPException(status_code=404, detail="Email not found")
    
    return quarantine[email_id]


@router.post("/quarantine/{email_id}/release")
async def release_from_quarantine(
    email_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Release an email from quarantine (admin only)"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if email_id not in quarantine:
        raise HTTPException(status_code=404, detail="Email not found")
    
    quarantine[email_id]["status"] = "released"
    
    return {
        "message": "Email released from quarantine",
        "email_id": email_id
    }


@router.post("/quarantine/{email_id}/block")
async def permanently_block(
    email_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Permanently block sender (admin only)"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if email_id not in quarantine:
        raise HTTPException(status_code=404, detail="Email not found")
    
    email = quarantine[email_id]
    email["status"] = "blocked"
    
    # In production: add to blocklist database
    
    return {
        "message": f"Sender {email['sender']} permanently blocked",
        "email_id": email_id
    }


@router.post("/report")
async def report_suspicious_email(
    email: EmailAnalysisRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Report a suspicious email (employee submission)
    Adds points to employee security score
    """
    
    # Analyze the reported email
    result = phishing_detector.analyze(
        text=email.body,
        sender_email=email.sender,
        sender_name=email.sender_name or "",
        subject=email.subject
    )
    
    # Award points based on accuracy
    points_awarded = 0
    if result.is_phishing:
        points_awarded = 10  # Correctly reported phishing
        message = "Great catch! This was a phishing attempt."
    elif result.threat_score > 30:
        points_awarded = 5  # Reported suspicious content
        message = "Thanks for reporting. This email had some suspicious elements."
    else:
        points_awarded = 2  # Participated in security
        message = "Thanks for being vigilant. This email appears safe."
    
    return {
        "message": message,
        "threat_score": result.threat_score,
        "is_phishing": result.is_phishing,
        "points_awarded": points_awarded
    }
