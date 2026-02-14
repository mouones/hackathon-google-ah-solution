"""
Sentinel Shield - Session & Cookie Protection API
Endpoints for session management and cookie theft prevention
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime

from .auth import get_current_user

# Import session protector
import sys
sys.path.append('..')
from modules.session_protector import SessionManager, USBKeyManager, BrowserProfileProtector

router = APIRouter()

# Initialize managers
session_manager = SessionManager()
usb_key_manager = USBKeyManager()


# Pydantic Models
class SessionCreateRequest(BaseModel):
    user_id: str
    usb_key_id: Optional[str] = None


class SessionValidateRequest(BaseModel):
    session_id: str
    usb_key_id: Optional[str] = None


class USBKeyRegisterRequest(BaseModel):
    key_id: str
    user_id: str


# API Endpoints

@router.get("/status")
async def get_session_protection_status(current_user: dict = Depends(get_current_user)):
    """Get session protection system status"""
    
    report = session_manager.get_session_report()
    
    return {
        "protection_enabled": True,
        "usb_key_required": session_manager.require_usb_key,
        "browser_protection_active": True,
        **report,
        "settings": {
            "session_timeout_minutes": session_manager.session_timeout_minutes,
            "max_inactive_minutes": session_manager.max_inactive_minutes
        }
    }


@router.post("/session/create")
async def create_secure_session(
    request: Request,
    session_request: SessionCreateRequest
):
    """Create a new secure session"""
    
    # Get client info
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Create session
    session = session_manager.create_session(
        user_id=session_request.user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        usb_key_id=session_request.usb_key_id
    )
    
    # Bind USB key if provided
    if session_request.usb_key_id:
        usb_key_manager.bind_key_to_session(session_request.usb_key_id, session.session_id)
    
    return {
        "session_id": session.session_id,
        "user_id": session.user_id,
        "created_at": session.created_at.isoformat(),
        "expires_at": session.expires_at.isoformat(),
        "device_fingerprint": session.device_fingerprint[:16] + "...",
        "usb_key_bound": session.usb_key_id is not None
    }


@router.post("/session/validate")
async def validate_session(
    request: Request,
    validate_request: SessionValidateRequest
):
    """Validate session and check for hijacking"""
    
    # Get client info
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Validate session
    is_valid = session_manager.validate_session(
        session_id=validate_request.session_id,
        ip_address=ip_address,
        user_agent=user_agent,
        usb_key_id=validate_request.usb_key_id
    )
    
    session = session_manager.active_sessions.get(validate_request.session_id)
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {
        "valid": is_valid,
        "session_id": validate_request.session_id,
        "status": session.status.value,
        "risk_score": session.risk_score,
        "anomalies_detected": len([a for a in session_manager.anomalies if a.session_id == validate_request.session_id]),
        "last_activity": session.last_activity.isoformat()
    }


@router.delete("/session/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Revoke a session"""
    
    session_manager.revoke_session(session_id)
    
    return {
        "session_id": session_id,
        "revoked": True,
        "revoked_at": datetime.now().isoformat(),
        "revoked_by": current_user["email"]
    }


@router.delete("/sessions/user/{user_id}")
async def revoke_all_user_sessions(
    user_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Revoke all sessions for a user"""
    
    session_manager.revoke_all_user_sessions(user_id)
    
    return {
        "user_id": user_id,
        "all_sessions_revoked": True,
        "revoked_at": datetime.now().isoformat()
    }


@router.get("/sessions/anomalies")
async def get_session_anomalies(
    severity: Optional[str] = None,
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get detected session anomalies"""
    
    anomalies = session_manager.anomalies
    
    # Filter by severity
    if severity:
        anomalies = [a for a in anomalies if a.severity == severity]
    
    # Sort by detection time (most recent first)
    anomalies = sorted(anomalies, key=lambda x: x.detected_at, reverse=True)
    
    return {
        "total_anomalies": len(anomalies),
        "critical": len([a for a in anomalies if a.severity == 'critical']),
        "high": len([a for a in anomalies if a.severity == 'high']),
        "anomalies": [
            {
                "anomaly_id": a.anomaly_id,
                "session_id": a.session_id,
                "anomaly_type": a.anomaly_type,
                "severity": a.severity,
                "description": a.description,
                "detected_at": a.detected_at.isoformat(),
                "indicators": a.indicators
            }
            for a in anomalies[:limit]
        ]
    }


@router.get("/browser-protection/status")
async def get_browser_protection_status(current_user: dict = Depends(get_current_user)):
    """Get browser profile protection status"""
    
    return {
        "protection_active": True,
        "monitored_browsers": ["Chrome", "Firefox", "Edge", "Brave"],
        "protected_paths_count": len(session_manager.browser_protector.monitored_paths),
        "blocked_access_attempts": len(session_manager.browser_protector.access_log),
        "terminated_processes": len(session_manager.browser_protector.blocked_processes),
        "recent_blocks": session_manager.browser_protector.access_log[-10:]
    }


@router.post("/browser-protection/scan")
async def scan_for_malicious_processes(current_user: dict = Depends(get_current_user)):
    """Scan for processes attempting to access browser credentials"""
    
    suspicious = session_manager.browser_protector.monitor_active_processes()
    
    return {
        "scan_timestamp": datetime.now().isoformat(),
        "suspicious_processes_found": len(suspicious),
        "processes": suspicious,
        "recommendation": "All suspicious processes have been terminated" if suspicious else "No threats detected"
    }


# USB Key Management Endpoints

@router.post("/usb-key/register")
async def register_usb_key(
    request: USBKeyRegisterRequest,
    current_user: dict = Depends(get_current_user)
):
    """Register a new USB security key"""
    
    success = usb_key_manager.register_key(request.key_id, request.user_id)
    
    return {
        "key_id": request.key_id,
        "user_id": request.user_id,
        "registered": success,
        "registered_at": datetime.now().isoformat()
    }


@router.post("/usb-key/verify")
async def verify_usb_key(
    key_id: str
):
    """Verify USB key and get associated user"""
    
    user_id = usb_key_manager.verify_key(key_id)
    
    if not user_id:
        raise HTTPException(status_code=404, detail="USB key not registered")
    
    return {
        "key_id": key_id,
        "verified": True,
        "user_id": user_id,
        "verified_at": datetime.now().isoformat()
    }


@router.get("/usb-key/{key_id}/session")
async def get_key_session(
    key_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get session bound to USB key"""
    
    session_id = usb_key_manager.get_session_for_key(key_id)
    
    if not session_id:
        return {
            "key_id": key_id,
            "session_bound": False
        }
    
    return {
        "key_id": key_id,
        "session_bound": True,
        "session_id": session_id
    }


@router.get("/report")
async def get_session_security_report(
    days: int = 7,
    current_user: dict = Depends(get_current_user)
):
    """Generate session security report"""
    
    report = session_manager.get_session_report()
    
    # Get recent anomalies
    recent_anomalies = [
        a for a in session_manager.anomalies
        if (datetime.now() - a.detected_at).days <= days
    ]
    
    return {
        "report_period": f"Last {days} days",
        "generated_at": datetime.now().isoformat(),
        **report,
        "anomalies_by_type": {
            "ip_change": len([a for a in recent_anomalies if a.anomaly_type == "ip_change"]),
            "user_agent_change": len([a for a in recent_anomalies if a.anomaly_type == "user_agent_change"]),
            "usb_key_mismatch": len([a for a in recent_anomalies if a.anomaly_type == "usb_key_mismatch"]),
            "inactivity_timeout": len([a for a in recent_anomalies if a.anomaly_type == "inactivity_timeout"])
        },
        "security_score": max(0, 100 - (len(recent_anomalies) * 5)),
        "recommendations": [
            "Enable USB key requirement for all users" if not session_manager.require_usb_key else "USB key protection active",
            f"Review {len(recent_anomalies)} detected anomalies" if recent_anomalies else "No anomalies detected",
            "Browser protection successfully blocked all malware access attempts" if report['browser_protection_blocks'] > 0 else "No malware attempts detected"
        ]
    }
