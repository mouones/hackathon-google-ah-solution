"""
Sentinel Shield - Email Viewer API Routes
Safe email rendering with threat highlighting and sandbox integration
"""

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict
import uuid
from datetime import datetime

# Import secure viewer
import sys
sys.path.append('..')
from modules.secure_email_viewer import SecureEmailViewer, SandboxPreview

router = APIRouter()

# Initialize viewer
email_viewer = SecureEmailViewer()
sandbox = SandboxPreview()


# Pydantic Models
class EmailViewRequest(BaseModel):
    email_id: str
    subject: str
    sender: str
    sender_name: Optional[str] = None
    body_html: str
    body_text: Optional[str] = None
    attachments: Optional[List[Dict]] = None


class HighlightInfo(BaseModel):
    element_type: str
    severity: str
    original_text: str
    explanation: str
    suggested_action: str


class EmailViewResponse(BaseModel):
    email_id: str
    safe_html: str
    highlights: List[HighlightInfo]
    has_attachments: bool
    attachment_risks: Dict[str, Dict]
    overall_risk: str
    can_preview: bool
    warning_message: Optional[str] = None


class AttachmentPreviewRequest(BaseModel):
    attachment_id: str
    filename: str
    use_sandbox: bool = True


class AdminSubmissionRequest(BaseModel):
    email_id: str
    reason: str
    user_comment: Optional[str] = None


@router.post("/view", response_model=EmailViewResponse)
async def view_email_safe(email: EmailViewRequest):
    """
    Render email safely with automatic threat highlighting
    
    - **email_id**: Unique email identifier
    - **subject**: Email subject line
    - **sender**: Sender email address
    - **body_html**: HTML body content
    - **attachments**: List of attachment metadata
    
    Returns sanitized HTML with highlighted threats
    """
    
    # Render email with security highlighting
    safe_email = email_viewer.render_safe(
        raw_html=email.body_html,
        subject=email.subject,
        sender=email.sender,
        attachments=email.attachments
    )
    
    # Convert highlights to response format
    highlights_response = [
        HighlightInfo(
            element_type=h.element_type,
            severity=h.severity,
            original_text=h.original_text,
            explanation=h.explanation,
            suggested_action=h.suggested_action
        )
        for h in safe_email.highlights
    ]
    
    # Generate warning message
    warning_message = None
    if safe_email.overall_risk == 'critical':
        warning_message = "⛔ CRITICAL THREAT DETECTED - Do not interact with this email. Submit to admin immediately."
    elif safe_email.overall_risk == 'dangerous':
        warning_message = "🚨 HIGH RISK - This email has multiple red flags. Exercise extreme caution."
    elif safe_email.overall_risk == 'suspicious':
        warning_message = "⚠️ SUSPICIOUS - Verify sender before taking any action."
    
    return EmailViewResponse(
        email_id=email.email_id,
        safe_html=safe_email.safe_html,
        highlights=highlights_response,
        has_attachments=safe_email.has_attachments,
        attachment_risks=safe_email.attachment_risks,
        overall_risk=safe_email.overall_risk,
        can_preview=safe_email.can_preview,
        warning_message=warning_message
    )


@router.post("/attachment/preview")
async def preview_attachment(
    request: AttachmentPreviewRequest,
    file: UploadFile = File(...)
):
    """
    Preview attachment safely
    
    - **use_sandbox**: If true, opens in isolated Docker sandbox
    - **file**: The attachment file to preview
    
    Returns safe preview or sandbox URL
    """
    
    # Read file content
    file_content = await file.read()
    
    if request.use_sandbox:
        # Open in sandbox
        sandbox_info = sandbox.open_in_sandbox(
            file_path=f"/tmp/{request.filename}",
            file_type=request.filename.split('.')[-1]
        )
        
        return {
            "preview_type": "sandbox",
            "sandbox_url": sandbox_info['url'],
            "sandbox_id": sandbox_info['sandbox_id'],
            "expires_in": sandbox_info['expires_in'],
            "message": "File opened in isolated sandbox environment"
        }
    else:
        # Create safe preview (no execution)
        safe_preview_html = sandbox.create_safe_preview(
            file_content=file_content,
            filename=request.filename
        )
        
        return {
            "preview_type": "safe_html",
            "html": safe_preview_html,
            "message": "Preview generated without executing file content"
        }


@router.post("/submit-to-admin")
async def submit_to_admin(submission: AdminSubmissionRequest):
    """
    Submit suspicious email to admin for analysis
    
    - **email_id**: Email to submit
    - **reason**: Why submitting (suspicious_link, malicious_attachment, etc.)
    - **user_comment**: Optional user comment
    
    Creates admin alert and queues for manual review
    """
    
    submission_id = str(uuid.uuid4())[:8]
    
    # In production: Store in database and create admin alert
    admin_submission = {
        "submission_id": submission_id,
        "email_id": submission.email_id,
        "reason": submission.reason,
        "user_comment": submission.user_comment,
        "submitted_at": datetime.now().isoformat(),
        "status": "pending_review",
        "priority": "high" if "malicious" in submission.reason else "medium"
    }
    
    print(f"📧 ADMIN SUBMISSION: Email {submission.email_id}")
    print(f"   Submission ID: {submission_id}")
    print(f"   Reason: {submission.reason}")
    
    return {
        "success": True,
        "submission_id": submission_id,
        "message": "Email submitted to security team for review",
        "estimated_response": "within 2 hours",
        "tracking_url": f"/admin/submissions/{submission_id}"
    }


@router.get("/highlights/examples")
async def get_highlight_examples():
    """
    Get example highlighted threats for user education
    
    Returns examples of what each type of highlight looks like
    """
    
    return {
        "examples": [
            {
                "type": "homoglyph",
                "example": "rn (looks like m)",
                "explanation": "Two letters that together look like a different letter",
                "danger": "Used to create fake domains like micr0soft.com"
            },
            {
                "type": "unicode_homoglyph",
                "example": "mіcrosoft.com (Cyrillic і)",
                "explanation": "Non-Latin characters that look identical to Latin letters",
                "danger": "Nearly impossible to spot visually"
            },
            {
                "type": "link_mismatch",
                "example": "Link says 'paypal.com' but goes to paypa1-secure.tk",
                "explanation": "Display text doesn't match actual destination",
                "danger": "Classic phishing technique"
            },
            {
                "type": "brand_impersonation",
                "example": "microsoft-security-team.com",
                "explanation": "Domain contains brand name but isn't official",
                "danger": "Impersonates trusted companies"
            },
            {
                "type": "urgency",
                "example": "Account suspended - immediate action required",
                "explanation": "Creates false urgency to pressure quick action",
                "danger": "Bypasses critical thinking"
            },
            {
                "type": "dangerous_attachment",
                "example": "invoice.pdf.exe",
                "explanation": "Executable disguised as document",
                "danger": "Can install malware when opened"
            }
        ]
    }


@router.get("/sandbox/{sandbox_id}")
async def get_sandbox_status(sandbox_id: str):
    """
    Check status of sandbox environment
    
    Returns sandbox status and remaining time
    """
    
    # In production: Query Docker container status
    return {
        "sandbox_id": sandbox_id,
        "status": "running",
        "remaining_time": 240,  # seconds
        "resource_usage": {
            "cpu": "5%",
            "memory": "128MB",
            "network": "disabled"
        },
        "security": {
            "isolation_level": "full",
            "network_access": False,
            "file_system": "read-only",
            "auto_destroy": True
        }
    }


@router.delete("/sandbox/{sandbox_id}")
async def destroy_sandbox(sandbox_id: str):
    """
    Manually destroy sandbox environment
    
    Stops and removes sandbox container
    """
    
    # In production: Stop and remove Docker container
    print(f"🗑️ Destroying sandbox: {sandbox_id}")
    
    return {
        "success": True,
        "message": f"Sandbox {sandbox_id} destroyed",
        "data_removed": True
    }
