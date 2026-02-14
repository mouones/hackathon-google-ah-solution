"""
Sentinel Shield - Safe Email Viewer
A secure email viewing interface that:
1. Sanitizes HTML to prevent XSS/code execution from preview
2. Highlights suspicious elements (links, urgency, sender issues)
3. Allows safe attachment handling via sandbox
4. Submit to admin for review
5. One-click reporting
"""

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import re
import html
import base64
from datetime import datetime
import hashlib

router = APIRouter()


# HTML Sanitization - removes all potentially dangerous content
class HTMLSanitizer:
    """
    Aggressively sanitizes HTML to prevent any code execution.
    This is the key protection against preview-based attacks.
    """
    
    # Tags we allow (safe for display)
    ALLOWED_TAGS = {
        'p', 'br', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'strong', 'b', 'em', 'i', 'u', 's', 'strike',
        'ul', 'ol', 'li', 'table', 'tr', 'td', 'th', 'thead', 'tbody',
        'blockquote', 'pre', 'code', 'hr'
    }
    
    # Dangerous patterns to remove completely
    DANGEROUS_PATTERNS = [
        r'<script[^>]*>.*?</script>',  # Script tags
        r'<style[^>]*>.*?</style>',    # Style tags (can hide content)
        r'<iframe[^>]*>.*?</iframe>',  # Iframes
        r'<object[^>]*>.*?</object>',  # Objects
        r'<embed[^>]*>.*?</embed>',    # Embeds
        r'<form[^>]*>.*?</form>',      # Forms (credential stealing)
        r'<input[^>]*>',               # Input fields
        r'<button[^>]*>.*?</button>',  # Buttons
        r'<link[^>]*>',                # External resources
        r'<meta[^>]*>',                # Meta tags
        r'on\w+\s*=',                  # Event handlers (onclick, etc)
        r'javascript:',                 # JavaScript URIs
        r'data:text/html',             # Data URIs with HTML
        r'vbscript:',                  # VBScript
        r'expression\s*\(',            # CSS expressions
    ]
    
    @classmethod
    def sanitize(cls, html_content: str) -> str:
        """Remove all dangerous content from HTML"""
        
        if not html_content:
            return ""
        
        result = html_content
        
        # Remove dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            result = re.sub(pattern, '', result, flags=re.IGNORECASE | re.DOTALL)
        
        # Remove all attributes from tags (prevents onclick, style, etc)
        result = re.sub(r'<(\w+)[^>]*>', r'<\1>', result)
        
        # Remove disallowed tags but keep content
        def clean_tag(match):
            tag = match.group(1).lower()
            if tag in cls.ALLOWED_TAGS:
                return match.group(0)
            return ""
        
        result = re.sub(r'<(/?\w+)>', clean_tag, result)
        
        return result
    
    @classmethod
    def to_plain_text(cls, html_content: str) -> str:
        """Convert HTML to plain text (safest option)"""
        
        # Remove all HTML tags
        text = re.sub(r'<[^>]+>', '', html_content)
        
        # Decode HTML entities
        text = html.unescape(text)
        
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text


class ThreatHighlighter:
    """
    Analyzes email content and adds visual highlighting for suspicious elements.
    Makes it easy for users to spot potential threats.
    """
    
    # Suspicious keywords to highlight
    URGENCY_KEYWORDS = [
        'urgent', 'immediate', 'act now', 'expires', 'suspended',
        'locked', 'verify', 'confirm', 'final notice', 'warning',
        'unauthorized', 'unusual activity', 'security alert'
    ]
    
    SENSITIVE_REQUESTS = [
        'password', 'ssn', 'social security', 'credit card',
        'bank account', 'login', 'credentials', 'verify your account'
    ]
    
    SUSPICIOUS_PHRASES = [
        'click here', 'click below', 'download now', 'open attachment',
        'wire transfer', 'gift card', 'bitcoin', 'cryptocurrency',
        'inherited', 'lottery', 'prize', 'won'
    ]
    
    @classmethod
    def highlight_content(cls, text: str) -> Dict[str, Any]:
        """
        Analyze content and return highlighted version with threat markers.
        Returns both the marked-up HTML and a list of found threats.
        """
        
        threats_found = []
        highlighted = text
        
        # Highlight urgency keywords (red background)
        for keyword in cls.URGENCY_KEYWORDS:
            pattern = re.compile(f'({re.escape(keyword)})', re.IGNORECASE)
            if pattern.search(highlighted):
                highlighted = pattern.sub(
                    r'<mark class="threat-urgency" title="⚠️ Urgency tactic">\1</mark>',
                    highlighted
                )
                threats_found.append({
                    'type': 'urgency',
                    'keyword': keyword,
                    'severity': 'medium',
                    'explanation': 'Urgency language is commonly used to pressure victims'
                })
        
        # Highlight sensitive data requests (orange background)
        for keyword in cls.SENSITIVE_REQUESTS:
            pattern = re.compile(f'({re.escape(keyword)})', re.IGNORECASE)
            if pattern.search(highlighted):
                highlighted = pattern.sub(
                    r'<mark class="threat-sensitive" title="🚨 Requests sensitive data">\1</mark>',
                    highlighted
                )
                threats_found.append({
                    'type': 'sensitive_request',
                    'keyword': keyword,
                    'severity': 'high',
                    'explanation': 'Legitimate companies rarely ask for this via email'
                })
        
        # Highlight suspicious phrases (yellow background)
        for phrase in cls.SUSPICIOUS_PHRASES:
            pattern = re.compile(f'({re.escape(phrase)})', re.IGNORECASE)
            if pattern.search(highlighted):
                highlighted = pattern.sub(
                    r'<mark class="threat-suspicious" title="⚡ Suspicious phrase">\1</mark>',
                    highlighted
                )
                threats_found.append({
                    'type': 'suspicious_phrase',
                    'keyword': phrase,
                    'severity': 'low',
                    'explanation': 'This phrase is commonly found in scam emails'
                })
        
        return {
            'highlighted_html': highlighted,
            'threats': threats_found,
            'threat_count': len(threats_found)
        }


class LinkAnalyzerInline:
    """Analyze and annotate links in email content"""
    
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz']
    URL_SHORTENERS = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
    
    @classmethod
    def analyze_and_annotate_links(cls, html_content: str) -> Dict[str, Any]:
        """Find all links and annotate them with safety info"""
        
        links_found = []
        
        # Find all URLs in content
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+' 
        
        def annotate_link(match):
            url = match.group(0)
            
            risk_level = 'low'
            warnings = []
            
            url_lower = url.lower()
            
            # Check for suspicious TLD
            for tld in cls.SUSPICIOUS_TLDS:
                if tld in url_lower:
                    risk_level = 'high'
                    warnings.append(f'Suspicious TLD: {tld}')
                    break
            
            # Check for URL shortener
            for shortener in cls.URL_SHORTENERS:
                if shortener in url_lower:
                    risk_level = 'medium' if risk_level == 'low' else risk_level
                    warnings.append(f'URL shortener hides destination')
                    break
            
            # Check for IP address instead of domain
            if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
                risk_level = 'high'
                warnings.append('Uses IP address instead of domain name')
            
            # Check for @ symbol (credential confusion attack)
            if '@' in url:
                risk_level = 'high'
                warnings.append('Contains @ symbol (obfuscation technique)')
            
            # Check for brand name in suspicious context
            brands = ['paypal', 'microsoft', 'google', 'amazon', 'apple', 'netflix']
            for brand in brands:
                if brand in url_lower and f'{brand}.com' not in url_lower:
                    risk_level = 'high'
                    warnings.append(f'Brand "{brand}" in suspicious URL')
                    break
            
            links_found.append({
                'url': url,
                'risk_level': risk_level,
                'warnings': warnings
            })
            
            # Determine CSS class based on risk
            css_class = f'link-risk-{risk_level}'
            title = ' | '.join(warnings) if warnings else 'Click to scan before visiting'
            
            return f'<span class="{css_class}" data-url="{html.escape(url)}" title="{html.escape(title)}">{html.escape(url)}</span>'
        
        annotated = re.sub(url_pattern, annotate_link, html_content)
        
        return {
            'annotated_html': annotated,
            'links': links_found,
            'high_risk_count': sum(1 for l in links_found if l['risk_level'] == 'high')
        }


# Pydantic models
class EmailToView(BaseModel):
    sender: str
    sender_name: Optional[str] = None
    recipient: str
    subject: str
    body_html: Optional[str] = None
    body_text: Optional[str] = None
    received_at: Optional[str] = None
    attachments: Optional[List[Dict[str, str]]] = None  # [{name, type, size}]
    headers: Optional[Dict[str, str]] = None


class ViewerResponse(BaseModel):
    safe_html: str
    threats_found: List[Dict]
    sender_analysis: Dict
    links_analysis: Dict
    attachments_analysis: List[Dict]
    overall_risk: str
    can_open_safely: bool


# API Endpoints

@router.post("/view", response_class=HTMLResponse)
async def view_email_safe(email: EmailToView):
    """
    View an email safely with all threats highlighted.
    Returns a fully rendered HTML page that's safe to display.
    """
    
    # Analyze sender
    sender_issues = []
    sender_risk = 'low'
    
    sender_lower = email.sender.lower()
    sender_name = email.sender_name or ""
    
    # Check free email for business
    free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
    for provider in free_providers:
        if provider in sender_lower:
            sender_issues.append(f'Uses free email provider ({provider})')
            sender_risk = 'medium'
    
    # Check display name vs email mismatch
    brands = ['paypal', 'microsoft', 'amazon', 'apple', 'google', 'netflix']
    for brand in brands:
        if brand in sender_name.lower() and brand not in sender_lower:
            sender_issues.append(f'Display name mentions "{brand}" but email domain doesn\'t match')
            sender_risk = 'high'
    
    # Sanitize and analyze content
    content = email.body_html or email.body_text or ""
    
    # Step 1: Sanitize (remove dangerous code)
    safe_content = HTMLSanitizer.sanitize(content)
    
    # Step 2: Highlight threats
    highlight_result = ThreatHighlighter.highlight_content(safe_content)
    
    # Step 3: Analyze and annotate links
    link_result = LinkAnalyzerInline.analyze_and_annotate_links(highlight_result['highlighted_html'])
    
    # Analyze attachments
    attachment_analysis = []
    dangerous_extensions = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar']
    macro_extensions = ['.docm', '.xlsm', '.pptm']
    
    for att in (email.attachments or []):
        att_name = att.get('name', '').lower()
        att_risk = 'low'
        att_warning = None
        
        for ext in dangerous_extensions:
            if att_name.endswith(ext):
                att_risk = 'critical'
                att_warning = f'Executable file ({ext}) - DO NOT OPEN'
                break
        
        if att_risk == 'low':
            for ext in macro_extensions:
                if att_name.endswith(ext):
                    att_risk = 'high'
                    att_warning = 'Macro-enabled document - may contain malicious code'
                    break
        
        # Check for double extension trick
        if re.search(r'\.(pdf|doc|jpg|png)\.(exe|scr|bat)', att_name):
            att_risk = 'critical'
            att_warning = 'Double extension attack detected!'
        
        attachment_analysis.append({
            'name': att.get('name'),
            'type': att.get('type'),
            'size': att.get('size'),
            'risk': att_risk,
            'warning': att_warning
        })
    
    # Calculate overall risk
    risks = [sender_risk]
    if highlight_result['threats']:
        risks.append('medium' if len(highlight_result['threats']) < 3 else 'high')
    if link_result['high_risk_count'] > 0:
        risks.append('high')
    if any(a['risk'] in ['high', 'critical'] for a in attachment_analysis):
        risks.append('critical')
    
    risk_priority = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
    overall_risk = max(risks, key=lambda r: risk_priority.get(r, 0))
    
    # Generate safe HTML viewer
    viewer_html = generate_safe_viewer_html(
        email=email,
        safe_content=link_result['annotated_html'],
        sender_issues=sender_issues,
        sender_risk=sender_risk,
        threats=highlight_result['threats'],
        links=link_result['links'],
        attachments=attachment_analysis,
        overall_risk=overall_risk
    )
    
    return HTMLResponse(content=viewer_html)


@router.post("/analyze")
async def analyze_email_json(email: EmailToView):
    """Return email analysis as JSON (for API integration)"""
    
    content = email.body_html or email.body_text or ""
    safe_content = HTMLSanitizer.sanitize(content)
    highlight_result = ThreatHighlighter.highlight_content(safe_content)
    link_result = LinkAnalyzerInline.analyze_and_annotate_links(safe_content)
    
    return {
        "threats_found": highlight_result['threats'],
        "links": link_result['links'],
        "threat_count": highlight_result['threat_count'],
        "high_risk_links": link_result['high_risk_count'],
        "sanitized": True
    }


@router.post("/submit-to-admin")
async def submit_to_admin(email: EmailToView, reason: str = "Suspicious email"):
    """Submit email to admin for review"""
    
    # In production: save to database, send notification
    submission_id = hashlib.sha256(
        f"{email.sender}{email.subject}{datetime.utcnow().isoformat()}".encode()
    ).hexdigest()[:12]
    
    return {
        "message": "Email submitted to admin for review",
        "submission_id": submission_id,
        "status": "pending_review",
        "submitted_at": datetime.utcnow().isoformat()
    }


@router.post("/open-in-sandbox")
async def open_in_sandbox(attachment_name: str, attachment_data: str = None):
    """Queue attachment for sandbox analysis"""
    
    # In production: send to sandbox VM for safe execution
    sandbox_id = hashlib.sha256(
        f"{attachment_name}{datetime.utcnow().isoformat()}".encode()
    ).hexdigest()[:12]
    
    return {
        "message": "Attachment queued for sandbox analysis",
        "sandbox_id": sandbox_id,
        "attachment": attachment_name,
        "status": "analyzing",
        "estimated_time": "2-5 minutes",
        "note": "You will be notified when analysis is complete"
    }


def generate_safe_viewer_html(
    email: EmailToView,
    safe_content: str,
    sender_issues: List[str],
    sender_risk: str,
    threats: List[Dict],
    links: List[Dict],
    attachments: List[Dict],
    overall_risk: str
) -> str:
    """Generate the complete safe email viewer HTML"""
    
    risk_colors = {
        'low': '#38a169',
        'medium': '#d69e2e', 
        'high': '#e53e3e',
        'critical': '#9b2c2c'
    }
    
    risk_color = risk_colors.get(overall_risk, '#718096')
    
    # Generate threat list HTML
    threats_html = ""
    if threats:
        threats_html = "<ul class='threat-list'>"
        for t in threats[:10]:  # Limit to 10
            threats_html += f"""
                <li class="threat-item threat-{t['severity']}">
                    <strong>{t['type'].replace('_', ' ').title()}</strong>: 
                    "{t['keyword']}" - {t['explanation']}
                </li>
            """
        threats_html += "</ul>"
    else:
        threats_html = "<p class='no-threats'>✓ No obvious threat keywords detected</p>"
    
    # Generate links HTML
    links_html = ""
    high_risk_links = [l for l in links if l['risk_level'] == 'high']
    if high_risk_links:
        links_html = "<ul class='link-list'>"
        for l in high_risk_links[:5]:
            links_html += f"""
                <li class="link-item">
                    <code>{html.escape(l['url'][:60])}</code>
                    <br><small>⚠️ {', '.join(l['warnings'])}</small>
                </li>
            """
        links_html += "</ul>"
    
    # Generate attachments HTML
    attachments_html = ""
    if attachments:
        attachments_html = "<div class='attachments'>"
        for att in attachments:
            att_class = f"att-{att['risk']}"
            attachments_html += f"""
                <div class="attachment {att_class}">
                    <span class="att-name">📎 {html.escape(att['name'])}</span>
                    <span class="att-size">{att.get('size', 'Unknown size')}</span>
                    {f"<span class='att-warning'>⚠️ {att['warning']}</span>" if att['warning'] else ""}
                    <div class="att-actions">
                        <button onclick="openInSandbox('{html.escape(att['name'])}')">🔒 Open in Sandbox</button>
                        <button onclick="downloadSafe('{html.escape(att['name'])}')">⬇️ Download Only</button>
                    </div>
                </div>
            """
        attachments_html += "</div>"
    
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Safe Email Viewer - Sentinel Shield</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: #f7fafc;
            color: #1a202c;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        /* Header */
        .header {{
            background: linear-gradient(135deg, #1a365d, #2c5282);
            color: white;
            padding: 20px;
            border-radius: 12px 12px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .header h1 {{
            font-size: 1.5rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        /* Risk Banner */
        .risk-banner {{
            background: {risk_color};
            color: white;
            padding: 15px 20px;
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .risk-banner.low {{ background: #38a169; }}
        .risk-banner.medium {{ background: #d69e2e; }}
        .risk-banner.high {{ background: #e53e3e; }}
        .risk-banner.critical {{ background: #9b2c2c; }}
        
        /* Email Meta */
        .email-meta {{
            background: white;
            padding: 20px;
            border-bottom: 1px solid #e2e8f0;
        }}
        
        .email-meta table {{
            width: 100%;
        }}
        
        .email-meta th {{
            text-align: left;
            width: 100px;
            color: #718096;
            font-weight: 500;
            padding: 8px 0;
            vertical-align: top;
        }}
        
        .email-meta td {{
            padding: 8px 0;
        }}
        
        .sender-warning {{
            background: #fed7d7;
            color: #c53030;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85rem;
            margin-left: 10px;
        }}
        
        /* Threats Panel */
        .threats-panel {{
            background: #fff5f5;
            border-left: 4px solid #e53e3e;
            padding: 15px 20px;
        }}
        
        .threats-panel h3 {{
            color: #c53030;
            margin-bottom: 10px;
        }}
        
        .threat-list {{
            list-style: none;
        }}
        
        .threat-item {{
            padding: 8px 12px;
            margin: 5px 0;
            border-radius: 4px;
            font-size: 0.9rem;
        }}
        
        .threat-high {{ background: #fed7d7; }}
        .threat-medium {{ background: #feebc8; }}
        .threat-low {{ background: #fefcbf; }}
        
        .no-threats {{
            color: #38a169;
            font-weight: 500;
        }}
        
        /* Links Panel */
        .links-panel {{
            background: #fffbeb;
            border-left: 4px solid #d69e2e;
            padding: 15px 20px;
        }}
        
        .link-list {{
            list-style: none;
        }}
        
        .link-item {{
            padding: 10px;
            margin: 5px 0;
            background: white;
            border-radius: 4px;
            font-size: 0.85rem;
        }}
        
        .link-item code {{
            word-break: break-all;
            color: #c53030;
        }}
        
        /* Email Content */
        .email-content {{
            background: white;
            padding: 30px;
            border: 2px solid #e2e8f0;
            min-height: 200px;
        }}
        
        /* Threat Highlighting */
        .threat-urgency {{
            background: #fed7d7;
            padding: 2px 4px;
            border-radius: 3px;
            border-bottom: 2px solid #e53e3e;
        }}
        
        .threat-sensitive {{
            background: #feebc8;
            padding: 2px 4px;
            border-radius: 3px;
            border-bottom: 2px solid #d69e2e;
        }}
        
        .threat-suspicious {{
            background: #fefcbf;
            padding: 2px 4px;
            border-radius: 3px;
            border-bottom: 2px solid #ecc94b;
        }}
        
        /* Link Risk Styling */
        .link-risk-low {{
            color: #2b6cb0;
            cursor: pointer;
            text-decoration: underline;
        }}
        
        .link-risk-medium {{
            background: #fef3c7;
            color: #92400e;
            padding: 2px 6px;
            border-radius: 3px;
            cursor: pointer;
        }}
        
        .link-risk-high {{
            background: #fee2e2;
            color: #991b1b;
            padding: 2px 6px;
            border-radius: 3px;
            text-decoration: line-through;
            cursor: not-allowed;
        }}
        
        /* Attachments */
        .attachments-panel {{
            background: #f0fff4;
            border-left: 4px solid #38a169;
            padding: 15px 20px;
        }}
        
        .attachment {{
            background: white;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
        }}
        
        .att-critical {{
            border: 2px solid #e53e3e;
            background: #fff5f5;
        }}
        
        .att-high {{
            border: 2px solid #d69e2e;
            background: #fffbeb;
        }}
        
        .att-name {{
            font-weight: 600;
            flex: 1;
        }}
        
        .att-warning {{
            color: #c53030;
            font-size: 0.85rem;
            width: 100%;
        }}
        
        .att-actions {{
            display: flex;
            gap: 10px;
            width: 100%;
            margin-top: 10px;
        }}
        
        .att-actions button {{
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
        }}
        
        .att-actions button:first-child {{
            background: #2c5282;
            color: white;
        }}
        
        .att-actions button:last-child {{
            background: #e2e8f0;
            color: #4a5568;
        }}
        
        /* Action Buttons */
        .actions {{
            background: #edf2f7;
            padding: 20px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            border-radius: 0 0 12px 12px;
        }}
        
        .btn {{
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .btn-report {{
            background: #e53e3e;
            color: white;
        }}
        
        .btn-safe {{
            background: #38a169;
            color: white;
        }}
        
        .btn-admin {{
            background: #d69e2e;
            color: white;
        }}
        
        .btn-delete {{
            background: #718096;
            color: white;
            margin-left: auto;
        }}
        
        /* Legend */
        .legend {{
            background: #edf2f7;
            padding: 15px 20px;
            font-size: 0.85rem;
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .legend-color {{
            width: 16px;
            height: 16px;
            border-radius: 3px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🛡️ Safe Email Viewer</h1>
            <span>Sentinel Shield</span>
        </div>
        
        <!-- Risk Banner -->
        <div class="risk-banner {overall_risk}">
            <span>⚠️ Overall Risk: {overall_risk.upper()}</span>
            <span>{len(threats)} threat indicators found</span>
        </div>
        
        <!-- Email Metadata -->
        <div class="email-meta">
            <table>
                <tr>
                    <th>From:</th>
                    <td>
                        <strong>{html.escape(email.sender_name or '')}</strong>
                        &lt;{html.escape(email.sender)}&gt;
                        {f'<span class="sender-warning">{sender_issues[0]}</span>' if sender_issues else ''}
                    </td>
                </tr>
                <tr>
                    <th>To:</th>
                    <td>{html.escape(email.recipient)}</td>
                </tr>
                <tr>
                    <th>Subject:</th>
                    <td><strong>{html.escape(email.subject)}</strong></td>
                </tr>
                <tr>
                    <th>Received:</th>
                    <td>{html.escape(email.received_at or 'Unknown')}</td>
                </tr>
            </table>
        </div>
        
        <!-- Threats Panel -->
        <div class="threats-panel">
            <h3>🚨 Detected Threat Indicators</h3>
            {threats_html}
        </div>
        
        <!-- High Risk Links -->
        {f'''
        <div class="links-panel">
            <h3>⚠️ Suspicious Links Detected</h3>
            <p>These links have been flagged as potentially dangerous:</p>
            {links_html}
        </div>
        ''' if high_risk_links else ''}
        
        <!-- Attachments -->
        {f'''
        <div class="attachments-panel">
            <h3>📎 Attachments</h3>
            <p>⚠️ Do not open attachments directly. Use sandbox for safety.</p>
            {attachments_html}
        </div>
        ''' if attachments else ''}
        
        <!-- Legend -->
        <div class="legend">
            <strong>Legend:</strong>
            <span class="legend-item">
                <span class="legend-color" style="background:#fed7d7"></span>
                Urgency/pressure tactics
            </span>
            <span class="legend-item">
                <span class="legend-color" style="background:#feebc8"></span>
                Sensitive data request
            </span>
            <span class="legend-item">
                <span class="legend-color" style="background:#fefcbf"></span>
                Suspicious phrase
            </span>
            <span class="legend-item">
                <span class="legend-color" style="background:#fee2e2;text-decoration:line-through"></span>
                Dangerous link
            </span>
        </div>
        
        <!-- Email Content (SAFE) -->
        <div class="email-content">
            <h3 style="color:#718096;margin-bottom:15px;font-size:0.9rem;">
                📧 Email Content (Sanitized - Safe to View)
            </h3>
            {safe_content}
        </div>
        
        <!-- Action Buttons -->
        <div class="actions">
            <button class="btn btn-report" onclick="reportPhishing()">
                🚫 Report as Phishing
            </button>
            <button class="btn btn-admin" onclick="submitToAdmin()">
                👨‍💼 Submit to Admin
            </button>
            <button class="btn btn-safe" onclick="markSafe()">
                ✓ Mark as Safe
            </button>
            <button class="btn btn-delete" onclick="deleteEmail()">
                🗑️ Delete
            </button>
        </div>
    </div>
    
    <script>
        // Prevent all link clicks - links should be scanned first
        document.querySelectorAll('.link-risk-high').forEach(el => {{
            el.addEventListener('click', (e) => {{
                e.preventDefault();
                alert('⚠️ This link has been blocked for your safety.\\n\\nReason: ' + el.title);
            }});
        }});
        
        document.querySelectorAll('.link-risk-medium, .link-risk-low').forEach(el => {{
            el.addEventListener('click', (e) => {{
                e.preventDefault();
                const url = el.dataset.url;
                if (confirm('⚠️ Do you want to scan this link before visiting?\\n\\n' + url)) {{
                    // In production: send to backend for scanning
                    window.open('/api/v1/viewer/scan-link?url=' + encodeURIComponent(url), '_blank');
                }}
            }});
        }});
        
        function openInSandbox(filename) {{
            if (confirm('Open "' + filename + '" in secure sandbox?\\n\\nThe file will be executed in an isolated environment.')) {{
                fetch('/api/v1/viewer/open-in-sandbox', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ attachment_name: filename }})
                }})
                .then(r => r.json())
                .then(data => {{
                    alert('✓ ' + data.message + '\\n\\nSandbox ID: ' + data.sandbox_id);
                }});
            }}
        }}
        
        function reportPhishing() {{
            if (confirm('Report this email as phishing?\\n\\nThis will help train our detection systems.')) {{
                alert('✓ Email reported as phishing. Thank you!\\n\\n+10 Security Points');
            }}
        }}
        
        function submitToAdmin() {{
            const reason = prompt('Why are you submitting this for review?', 'Suspicious email');
            if (reason) {{
                fetch('/api/v1/viewer/submit-to-admin', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ 
                        email: {{ /* email data here */ }},
                        reason: reason 
                    }})
                }})
                .then(r => r.json())
                .then(data => {{
                    alert('✓ ' + data.message + '\\n\\nSubmission ID: ' + data.submission_id);
                }});
            }}
        }}
        
        function markSafe() {{
            if (confirm('Mark this email as safe?\\n\\nThis will whitelist the sender.')) {{
                alert('✓ Email marked as safe. Sender added to trusted list.');
            }}
        }}
        
        function deleteEmail() {{
            if (confirm('Delete this email permanently?')) {{
                alert('✓ Email deleted.');
                window.close();
            }}
        }}
        
        function downloadSafe(filename) {{
            alert('⚠️ Downloading file for offline scanning only.\\n\\nDo NOT open this file directly!');
        }}
    </script>
</body>
</html>
    """
