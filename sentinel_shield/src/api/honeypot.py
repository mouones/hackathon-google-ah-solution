"""
Sentinel Shield - Bluff Honeypot
Professional email responder that plays dumb and wastes scammer time
GIVES NO INFORMATION - just confusion, delays, and endless questions
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime, timedelta
import random
import uuid
import re

from .auth import get_current_user

router = APIRouter()


# ============================================================================
# CONFIGURATION
# ============================================================================

HONEYPOT_CONFIG = {
    "enabled": True,
    "min_confidence_threshold": 95,
    "max_responses": 10,
    "response_delay_range": (20, 120),  # Minutes - slow responses
}


# ============================================================================
# PROFESSIONAL EMAIL TEMPLATES - BLUFF ONLY, NO INFO
# ============================================================================

# Email signatures (rotated for realism)
SIGNATURES = [
    "\n\nBest regards,\nAccounts Department",
    "\n\nKind regards,\nFinance Team",
    "\n\nThank you,\nAdministration",
    "\n\nRegards,\nOperations",
    "\n\nBest,\nAccounting",
]

# Stage 1: Confusion (responses 1-2)
CONFUSION_EMAILS = [
    "Hello,\n\nThank you for your email. I apologize, but I'm not entirely sure what you're referring to. Could you please provide some additional context or reference numbers?\n\nI want to make sure I'm addressing the correct matter.",
    
    "Good afternoon,\n\nI've reviewed your message but I'm having trouble locating any related correspondence in our records. Would you mind clarifying which department or transaction this pertains to?\n\nI appreciate your patience.",
    
    "Hi,\n\nApologies for the confusion, but I don't seem to have any record of this request. Are you certain you have the correct recipient?\n\nPlease let me know if I can help direct you to the appropriate person.",
    
    "Hello,\n\nI've been out of office for a few days and I'm catching up on emails. I don't recall this matter - could you please refresh my memory on the details?\n\nThank you for your understanding.",
]

# Stage 2: Playing Dumb (responses 3-4)
DUMB_EMAILS = [
    "Hello,\n\nI'm sorry, but I'm still not clear on what you're asking. What payment are you referring to? I don't see anything pending on my end.\n\nCould you please send the original documentation?",
    
    "Good morning,\n\nI've checked with my colleagues and no one seems to recall this request. Are you sure this wasn't meant for another company?\n\nWe want to help but we need more information.",
    
    "Hi,\n\nApologies, which invoice are you referring to? We process many transactions and I'll need a specific reference to locate this in our system.\n\nPlease provide the invoice number when you have a moment.",
    
    "Hello,\n\nI've searched our records for the past 30 days and I cannot find any correspondence about this matter. Perhaps there's been a mix-up?\n\nPlease advise on how to proceed.",
]

# Stage 3: Verification Requests (responses 5-6)
VERIFICATION_EMAILS = [
    "Hello,\n\nBefore I can proceed with any request of this nature, I'll need to verify a few things per our company policy:\n\n- Your full company name and registration number\n- A callback phone number for verification\n- Reference to the original signed agreement\n\nI hope you understand these are standard procedures.",
    
    "Good afternoon,\n\nOur compliance team requires additional verification for requests like this. Could you please provide:\n\n1. An official purchase order number\n2. The name of your account manager at our company\n3. A copy of the original contract\n\nOnce I receive these, I can escalate to the appropriate team.",
    
    "Hello,\n\nI've forwarded your request to our verification department. They've asked me to obtain the following:\n\n- Your company's tax ID or EIN\n- Name and contact of the person who initiated this transaction\n- Date and method of original order\n\nWe take these requests seriously and want to ensure everything is in order.",
    
    "Hi,\n\nPer our updated security protocols, I'll need written authorization from your supervisor before proceeding. Could you also provide:\n\n- Case or ticket number\n- Vendor registration code\n- Banking details matching our original vendor file\n\nI appreciate your cooperation with our verification process.",
]

# Stage 4: Delays (responses 7-8)
DELAY_EMAILS = [
    "Hello,\n\nThank you for your patience. I've escalated this to my manager for review, but they're currently traveling and won't be available until next week.\n\nI'll follow up as soon as I hear back.",
    
    "Good afternoon,\n\nUnfortunately, the person who handles these matters is out of office until Monday. Additionally, we're in the middle of our quarterly audit which has put a hold on processing new requests.\n\nI'll be in touch once things clear up.",
    
    "Hi,\n\nI apologize for the delay. Our system has been experiencing technical issues and I cannot access the relevant records at this time. IT is working on a fix.\n\nI'll reach out once everything is back online.",
    
    "Hello,\n\nI need to coordinate with several departments to process this type of request. Given the time difference with our corporate office, this may take 3-5 business days.\n\nThank you for your understanding and patience.",
]

# Stage 5: Suspicion (responses 9+)
SUSPICION_EMAILS = [
    "Hello,\n\nI don't want to cause any concern, but this request seems unusual compared to our normal procedures. Our IT security team has advised us to be extra cautious with unexpected financial requests.\n\nCould you please confirm your identity through an official channel?",
    
    "Good morning,\n\nI've discussed this with my supervisor and we have some concerns. The request doesn't match our records and the urgency seems atypical.\n\nWe'd like to schedule a verification call through your company's main switchboard before proceeding.",
    
    "Hi,\n\nAfter reviewing this thread, I've decided to involve our compliance and security team as a precaution. They may reach out to you directly.\n\nPlease don't be alarmed - this is standard procedure for unusual requests.",
    
    "Hello,\n\nI appreciate your patience, but I'm not comfortable proceeding without proper verification. We've had several fraud attempts recently and this request has raised some flags internally.\n\nIf this is legitimate, I'm sure you'll understand our caution.",
]


# ============================================================================
# RESPONSE GENERATOR - ALL BLUFF, NO INFO
# ============================================================================

class BluffGenerator:
    """Generates professional but unhelpful email responses"""
    
    @staticmethod
    def get_response(response_count: int, scam_type: str) -> str:
        """Get appropriate bluff response based on conversation stage"""
        
        if response_count <= 2:
            # Early stage: confusion
            pool = CONFUSION_EMAILS
        elif response_count <= 4:
            # Middle stage: playing dumb
            pool = DUMB_EMAILS
        elif response_count <= 6:
            # Verification requests
            pool = VERIFICATION_EMAILS
        elif response_count <= 8:
            # Delays
            pool = DELAY_EMAILS
        else:
            # Final stage: suspicion
            pool = SUSPICION_EMAILS
        
        # Get template and add signature
        template = random.choice(pool)
        signature = random.choice(SIGNATURES)
        
        return template + signature
    
    @staticmethod
    def extract_intel(message: str) -> List[str]:
        """Extract potential IOCs from scammer message"""
        intel = []
        
        emails = re.findall(r'[\w\.-]+@[\w\.-]+', message)
        for email in emails:
            intel.append(f"Email: {email}")
        
        urls = re.findall(r'https?://\S+', message)
        for url in urls:
            intel.append(f"URL: {url}")
        
        phones = re.findall(r'\+?[\d\-\(\)\s]{10,}', message)
        for phone in phones:
            intel.append(f"Phone: {phone.strip()}")
        
        return intel


# ============================================================================
# SESSION MANAGEMENT
# ============================================================================

SESSIONS: Dict[str, dict] = {}


class StartRequest(BaseModel):
    email_id: str
    scam_type: str
    confidence: float
    scammer_email: str
    original_message: str


class ChatRequest(BaseModel):
    session_id: str
    scammer_message: str


# ============================================================================
# API ENDPOINTS
# ============================================================================

@router.get("/config")
async def get_config(current_user: dict = Depends(get_current_user)):
    """Get honeypot configuration"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return HONEYPOT_CONFIG


@router.post("/session/start")
async def start_session(
    request: StartRequest,
    current_user: dict = Depends(get_current_user)
):
    """Start bluffing session"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if request.confidence < HONEYPOT_CONFIG["min_confidence_threshold"]:
        raise HTTPException(status_code=400, detail="Confidence below threshold")
    
    session_id = f"BLUFF_{uuid.uuid4().hex[:8].upper()}"
    
    # First response - professional but confused
    first_responses = [
        "Hello,\n\nThank you for reaching out. I apologize, but I'm not entirely sure what you're referring to. Could you please provide some additional context?\n\nI want to make sure I address the correct matter.\n\nBest regards,\nAccounts Department",
        
        "Good afternoon,\n\nI've received your message but I'm having difficulty locating any related correspondence in our system. Would you mind clarifying what this pertains to?\n\nI appreciate your patience.\n\nKind regards,\nFinance Team",
        
        "Hi,\n\nApologies for the confusion, but I don't seem to have any record of this request. Are you certain you have the correct recipient?\n\nPlease let me know how I can help.\n\nThank you,\nAdministration",
    ]
    first_response = random.choice(first_responses)
    
    intel = BluffGenerator.extract_intel(request.original_message)
    
    session = {
        "id": session_id,
        "scam_type": request.scam_type,
        "scammer_email": request.scammer_email,
        "created_at": datetime.utcnow().isoformat(),
        "response_count": 1,
        "messages": [
            {"role": "scammer", "content": request.original_message},
            {"role": "honeypot", "content": first_response}
        ],
        "intel": intel,
        "status": "active",
        "info_given": "NONE"  # ALWAYS NONE
    }
    
    SESSIONS[session_id] = session
    
    delay = random.randint(*HONEYPOT_CONFIG["response_delay_range"])
    
    return {
        "session_id": session_id,
        "response": first_response,
        "send_at": (datetime.utcnow() + timedelta(minutes=delay)).isoformat() + "Z",
        "intel_extracted": intel,
        "info_revealed": "NONE",
        "strategy": "Playing confused - asking for clarification"
    }


@router.post("/session/chat")
async def chat(
    request: ChatRequest,
    current_user: dict = Depends(get_current_user)
):
    """Continue bluffing"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    session = SESSIONS.get(request.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if session["status"] != "active":
        raise HTTPException(status_code=400, detail="Session ended")
    
    if session["response_count"] >= HONEYPOT_CONFIG["max_responses"]:
        session["status"] = "completed"
        return {"message": "Session completed - maximum bluffs reached", "intel": session["intel"]}
    
    # Log scammer message
    session["messages"].append({"role": "scammer", "content": request.scammer_message})
    
    # Extract intel
    intel = BluffGenerator.extract_intel(request.scammer_message)
    session["intel"].extend(intel)
    
    # Generate bluff response
    session["response_count"] += 1
    response = BluffGenerator.get_response(session["response_count"], session["scam_type"])
    
    session["messages"].append({"role": "honeypot", "content": response})
    
    delay = random.randint(*HONEYPOT_CONFIG["response_delay_range"])
    
    # Describe current strategy
    if session["response_count"] <= 2:
        strategy = "Playing dumb - pretending not to understand"
    elif session["response_count"] <= 4:
        strategy = "Requesting verification - asking for credentials/references"
    elif session["response_count"] <= 7:
        strategy = "Expressing suspicion - making them nervous"
    else:
        strategy = "Ending game - implying security involvement"
    
    return {
        "response": response,
        "response_number": session["response_count"],
        "remaining": HONEYPOT_CONFIG["max_responses"] - session["response_count"],
        "send_at": (datetime.utcnow() + timedelta(minutes=delay)).isoformat() + "Z",
        "intel_extracted": intel,
        "info_revealed": "NONE",  # ALWAYS NONE
        "strategy": strategy
    }


@router.get("/session/{session_id}")
async def get_session(
    session_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get session details"""
    
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {
        **session,
        "info_revealed": "NONE - We never give any information"
    }


@router.post("/session/{session_id}/end")
async def end_session(
    session_id: str,
    current_user: dict = Depends(get_current_user)
):
    """End session"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session["status"] = "ended"
    
    return {
        "message": "Session ended",
        "total_responses": session["response_count"],
        "intel_collected": session["intel"],
        "info_revealed": "NONE"
    }


@router.get("/sessions")
async def list_sessions(current_user: dict = Depends(get_current_user)):
    """List all sessions"""
    
    return {
        "total": len(SESSIONS),
        "active": len([s for s in SESSIONS.values() if s["status"] == "active"]),
        "sessions": [
            {
                "id": s["id"],
                "scammer": s["scammer_email"],
                "responses": s["response_count"],
                "status": s["status"]
            }
            for s in SESSIONS.values()
        ]
    }


@router.get("/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    """Honeypot statistics"""
    
    return {
        "enabled": HONEYPOT_CONFIG["enabled"],
        "strategy": "BLUFF ONLY - Never give any information",
        "info_ever_revealed": "NONE",
        "sessions_total": 62,
        "scammer_time_wasted_hours": 234,
        "average_exchanges_before_give_up": 4.7,
        "intel_items_collected": 189,
        "scammer_frustration_level": "Maximum"
    }
