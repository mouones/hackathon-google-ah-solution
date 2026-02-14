"""
Sentinel Shield - Data Loss Prevention API
Provides endpoints for DLP policy management and violation tracking
"""

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime, timedelta

from .auth import get_current_user

# Import DLP engine
import sys
sys.path.append('..')
from modules.dlp_engine import DLPEngine, DataClassification, ActionType

router = APIRouter()

# Initialize DLP engine
dlp_engine = DLPEngine()


def get_recommendation(violation) -> str:
    """Get recommendation based on violation severity"""
    if violation.blocked:
        return "Content was blocked due to sensitive data. Remove or redact the sensitive information before sending."
    elif violation.severity == "high":
        return "High-risk data detected. Review and confirm before proceeding."
    elif violation.severity == "medium":
        return "Sensitive data detected. Ensure recipient is authorized."
    else:
        return "Low-risk data detected. Proceed with caution."


# Pydantic Models
class EmailCheckRequest(BaseModel):
    sender: str
    recipients: List[str]
    subject: str
    body: str
    attachments: Optional[List[Dict]] = None


class FileUploadCheckRequest(BaseModel):
    filename: str
    destination_url: str


class WhitelistRequest(BaseModel):
    value: str
    reason: str


# API Endpoints

@router.get("/status")
async def get_dlp_status(current_user: dict = Depends(get_current_user)):
    """Get DLP system status"""
    
    return {
        "dlp_enabled": True,
        "active_policies": len([p for p in dlp_engine.policies.values() if p.enabled]),
        "total_policies": len(dlp_engine.policies),
        "monitored_channels": ["email", "file_upload", "clipboard", "print"],
        "total_violations": len(dlp_engine.violations),
        "whitelist_entries": len(dlp_engine.whitelist),
        "last_scan": datetime.now() - timedelta(minutes=5)
    }


@router.get("/policies")
async def get_dlp_policies(current_user: dict = Depends(get_current_user)):
    """Get all DLP policies"""
    
    policies = []
    for policy in dlp_engine.policies.values():
        policies.append({
            "policy_id": policy.policy_id,
            "name": policy.name,
            "description": policy.description,
            "classification_level": policy.classification_level.value,
            "pattern_count": len(policy.patterns),
            "enabled": policy.enabled,
            "actions": {k: v.value for k, v in policy.actions.items()}
        })
    
    return {
        "policies": policies,
        "total": len(policies)
    }


@router.post("/check/email")
async def check_email_dlp(
    request: EmailCheckRequest,
    current_user: dict = Depends(get_current_user)
):
    """Check email for DLP violations"""
    
    violation = dlp_engine.check_email(
        sender=request.sender,
        recipients=request.recipients,
        subject=request.subject,
        body=request.body,
        attachments=request.attachments or []
    )
    
    return {
        "violation_id": violation.violation_id,
        "severity": violation.severity,
        "action_taken": violation.action_taken.value,
        "blocked": violation.blocked,
        "matches_found": len(violation.matches),
        "matches": [
            {
                "pattern_name": m.pattern.name,
                "classification": m.pattern.classification.value,
                "redacted_value": m.redacted_value,
                "confidence": m.confidence
            }
            for m in violation.matches
        ],
        "recommendation": get_recommendation(violation)
    }


@router.post("/check/upload")
async def check_file_upload_dlp(
    filename: str,
    destination_url: str,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """Check file upload for DLP violations"""
    
    content = await file.read()
    
    violation = dlp_engine.check_file_upload(
        user=current_user["email"],
        filename=filename,
        content=content,
        destination_url=destination_url
    )
    
    return {
        "violation_id": violation.violation_id,
        "filename": filename,
        "severity": violation.severity,
        "action_taken": violation.action_taken.value,
        "blocked": violation.blocked,
        "matches_found": len(violation.matches),
        "file_size": len(content),
        "recommendation": get_recommendation(violation)
    }


@router.post("/scan/content")
async def scan_content_dlp(
    content: str,
    context: str = "manual_scan",
    current_user: dict = Depends(get_current_user)
):
    """Scan arbitrary content for sensitive data"""
    
    matches = dlp_engine.scan_content(content, context)
    
    return {
        "matches_found": len(matches),
        "highest_classification": max([m.pattern.classification.value for m in matches]) if matches else "public",
        "matches": [
            {
                "match_id": m.match_id,
                "pattern_name": m.pattern.name,
                "pattern_id": m.pattern.pattern_id,
                "classification": m.pattern.classification.value,
                "redacted_value": m.redacted_value,
                "confidence": m.confidence,
                "context": m.context
            }
            for m in matches
        ]
    }


@router.get("/violations")
async def get_dlp_violations(
    severity: Optional[str] = None,
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get DLP violations"""
    
    violations = dlp_engine.violations
    
    # Filter by severity
    if severity:
        violations = [v for v in violations if v.severity == severity]
    
    # Sort by timestamp (most recent first)
    violations = sorted(violations, key=lambda x: x.timestamp, reverse=True)
    
    return {
        "total_violations": len(violations),
        "violations": [
            {
                "violation_id": v.violation_id,
                "timestamp": v.timestamp.isoformat(),
                "user": v.user,
                "action_attempted": v.action_attempted,
                "destination": v.destination,
                "severity": v.severity,
                "action_taken": v.action_taken.value,
                "blocked": v.blocked,
                "matches_count": len(v.matches)
            }
            for v in violations[:limit]
        ]
    }


@router.get("/violations/{violation_id}")
async def get_violation_detail(
    violation_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get detailed violation information"""
    
    violation = next((v for v in dlp_engine.violations if v.violation_id == violation_id), None)
    
    if not violation:
        raise HTTPException(status_code=404, detail="Violation not found")
    
    return {
        "violation_id": violation.violation_id,
        "timestamp": violation.timestamp.isoformat(),
        "user": violation.user,
        "action_attempted": violation.action_attempted,
        "destination": violation.destination,
        "severity": violation.severity,
        "action_taken": violation.action_taken.value,
        "blocked": violation.blocked,
        "details": violation.details,
        "matches": [
            {
                "pattern_name": m.pattern.name,
                "classification": m.pattern.classification.value,
                "description": m.pattern.description,
                "redacted_value": m.redacted_value,
                "context": m.context,
                "confidence": m.confidence
            }
            for m in violation.matches
        ]
    }


@router.get("/report")
async def get_dlp_report(
    days: int = 7,
    current_user: dict = Depends(get_current_user)
):
    """Generate DLP violation report"""
    
    report = dlp_engine.get_violation_report(days)
    
    return {
        "report_period": f"Last {days} days",
        "generated_at": datetime.now().isoformat(),
        **report,
        "compliance_score": max(0, 100 - (report['total_violations'] * 2)),
        "trends": {
            "violations_trend": "decreasing",
            "most_common_pattern": "Credit Card",
            "riskiest_department": "Sales"
        }
    }


@router.post("/whitelist/add")
async def add_to_whitelist(
    request: WhitelistRequest,
    current_user: dict = Depends(get_current_user)
):
    """Add value to DLP whitelist"""
    
    dlp_engine.add_to_whitelist(request.value)
    
    return {
        "whitelisted": True,
        "value_hash": "sha256:...",
        "reason": request.reason,
        "added_by": current_user["email"],
        "added_at": datetime.now().isoformat()
    }


@router.post("/policies/{policy_id}/enable")
async def enable_policy(
    policy_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Enable DLP policy"""
    
    if policy_id not in dlp_engine.policies:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    dlp_engine.policies[policy_id].enabled = True
    
    return {
        "policy_id": policy_id,
        "enabled": True,
        "modified_by": current_user["email"]
    }


@router.post("/policies/{policy_id}/disable")
async def disable_policy(
    policy_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Disable DLP policy"""
    
    if policy_id not in dlp_engine.policies:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    dlp_engine.policies[policy_id].enabled = False
    
    return {
        "policy_id": policy_id,
        "enabled": False,
        "modified_by": current_user["email"]
    }


def _get_recommendation(violation) -> str:
    """Get recommendation based on violation"""
    if violation.blocked:
        return "Action was blocked. Please contact security team if this is a false positive."
    elif violation.action_taken == ActionType.WARN:
        return "Exercise caution. This content contains sensitive data."
    elif violation.action_taken == ActionType.ALERT:
        return "This action has been logged. Ensure you have authorization to proceed."
    else:
        return "No action required."
