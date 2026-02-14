"""
Sentinel Shield - Secure Email Viewer
Safe email rendering with automatic threat highlighting and sandbox integration
"""

import re
import html
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import base64


@dataclass
class EmailHighlight:
    """Represents a highlighted suspicious element"""
    element_type: str  # homoglyph, link, attachment, urgency, etc.
    severity: str  # critical, high, medium, low
    start_pos: int
    end_pos: int
    original_text: str
    explanation: str
    suggested_action: str


@dataclass
class SafeEmail:
    """Safely rendered email with highlights"""
    safe_html: str
    highlights: List[EmailHighlight]
    has_attachments: bool
    attachment_risks: Dict[str, str]
    overall_risk: str
    can_preview: bool


class HomoglyphHighlighter:
    """Highlights character substitution attacks"""
    
    # Dangerous character combinations that look like other letters
    LOOKALIKE_PATTERNS = {
        'rn': ('m', 'Two letters "r" and "n" together look like "m"'),
        'vv': ('w', 'Two letters "v" together look like "w"'),
        'cl': ('d', 'Letters "c" and "l" together look like "d"'),
        'nn': ('m', 'Two letters "n" together look like "m"'),
        'ri': ('n', 'Letters "r" and "i" together look like "n"'),
        'lI': ('d', 'Lowercase "l" and uppercase "I" look like "d"'),
    }
    
    # Unicode lookalikes
    UNICODE_LOOKALIKES = {
        'а': ('a', 'Cyrillic "а" (U+0430) looks like Latin "a"'),
        'е': ('e', 'Cyrillic "е" (U+0435) looks like Latin "e"'),
        'о': ('o', 'Cyrillic "о" (U+043E) looks like Latin "o"'),
        'р': ('p', 'Cyrillic "р" (U+0440) looks like Latin "p"'),
        'с': ('c', 'Cyrillic "с" (U+0441) looks like Latin "c"'),
        'у': ('y', 'Cyrillic "у" (U+0443) looks like Latin "y"'),
        'і': ('i', 'Cyrillic "і" (U+0456) looks like Latin "i"'),
        'ο': ('o', 'Greek "ο" (omicron) looks like Latin "o"'),
        'α': ('a', 'Greek "α" (alpha) looks like Latin "a"'),
        '0': ('O', 'Number zero looks like letter O'),
        '1': ('l', 'Number one looks like letter l'),
    }
    
    @classmethod
    def highlight(cls, text: str) -> Tuple[str, List[EmailHighlight]]:
        """Highlight lookalike characters in text"""
        highlights = []
        highlighted_text = text
        offset = 0
        
        # Check ASCII patterns
        for pattern, (looks_like, explanation) in cls.LOOKALIKE_PATTERNS.items():
            for match in re.finditer(re.escape(pattern), text, re.IGNORECASE):
                start, end = match.span()
                
                # Wrap in highlight span
                highlight_html = f'<span class="homoglyph-highlight" data-looks-like="{looks_like}" title="{explanation}">{match.group()}</span>'
                
                highlights.append(EmailHighlight(
                    element_type='homoglyph',
                    severity='high',
                    start_pos=start,
                    end_pos=end,
                    original_text=match.group(),
                    explanation=explanation,
                    suggested_action=f'Verify if this should be "{looks_like}" instead'
                ))
        
        # Check Unicode lookalikes
        for i, char in enumerate(text):
            if char in cls.UNICODE_LOOKALIKES:
                looks_like, explanation = cls.UNICODE_LOOKALIKES[char]
                highlights.append(EmailHighlight(
                    element_type='unicode_homoglyph',
                    severity='critical',
                    start_pos=i,
                    end_pos=i + 1,
                    original_text=char,
                    explanation=explanation,
                    suggested_action=f'This character is not a normal "{looks_like}"'
                ))
        
        return highlighted_text, highlights


class LinkHighlighter:
    """Highlights suspicious links"""
    
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.work', '.click']
    BRAND_NAMES = ['microsoft', 'google', 'paypal', 'amazon', 'apple', 'facebook', 'netflix']
    
    @classmethod
    def highlight(cls, html_content: str) -> Tuple[str, List[EmailHighlight]]:
        """Highlight suspicious links"""
        soup = BeautifulSoup(html_content, 'html.parser')
        highlights = []
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            display_text = link.get_text()
            
            # Check for link/display mismatch
            mismatch = cls._check_mismatch(href, display_text)
            if mismatch:
                highlights.append(EmailHighlight(
                    element_type='link_mismatch',
                    severity='critical',
                    start_pos=0,
                    end_pos=0,
                    original_text=display_text,
                    explanation=f'Link text says "{display_text}" but goes to {href}',
                    suggested_action='DO NOT CLICK - This is likely phishing'
                ))
                
                # Add visual warning to link
                link['class'] = link.get('class', []) + ['suspicious-link', 'link-mismatch']
                link['data-actual-url'] = href
                link['data-warning'] = 'Link destination does not match display text'
            
            # Check for suspicious TLD
            parsed = urlparse(href)
            domain = parsed.netloc.lower()
            
            if any(domain.endswith(tld) for tld in cls.SUSPICIOUS_TLDS):
                highlights.append(EmailHighlight(
                    element_type='suspicious_tld',
                    severity='high',
                    start_pos=0,
                    end_pos=0,
                    original_text=domain,
                    explanation=f'Domain uses suspicious TLD commonly used for phishing',
                    suggested_action='Verify sender before clicking'
                ))
                
                link['class'] = link.get('class', []) + ['suspicious-link', 'suspicious-tld']
            
            # Check for brand impersonation
            for brand in cls.BRAND_NAMES:
                if brand in domain and not domain.endswith(f'{brand}.com'):
                    highlights.append(EmailHighlight(
                        element_type='brand_impersonation',
                        severity='critical',
                        start_pos=0,
                        end_pos=0,
                        original_text=domain,
                        explanation=f'Domain contains "{brand}" but is not the official {brand}.com',
                        suggested_action='DANGER - Likely phishing attempt'
                    ))
                    
                    link['class'] = link.get('class', []) + ['suspicious-link', 'brand-impersonation']
        
        return str(soup), highlights
    
    @staticmethod
    def _check_mismatch(href: str, display_text: str) -> bool:
        """Check if link destination mismatches display text"""
        if not display_text:
            return False
        
        # Extract domain from href
        parsed = urlparse(href)
        href_domain = parsed.netloc.lower()
        
        # Check if display looks like a URL but points elsewhere
        url_pattern = r'https?://[\w\.-]+|[\w\.-]+\.(com|org|net|edu|gov)'
        if re.search(url_pattern, display_text.lower()):
            display_domain = re.search(r'[\w\.-]+\.(com|org|net|edu|gov)', display_text.lower())
            if display_domain and display_domain.group() not in href_domain:
                return True
        
        return False


class UrgencyDetector:
    """Detects urgency manipulation tactics"""
    
    URGENCY_KEYWORDS = {
        'critical': [
            'account suspended', 'account terminated', 'account locked',
            'unauthorized access', 'security breach', 'immediate action required',
            'within 24 hours', 'expires today', 'act now', 'urgent'
        ],
        'high': [
            'verify your account', 'confirm your identity', 'update payment',
            'suspicious activity', 'unusual activity', 'limited time',
            'final notice', 'last chance'
        ]
    }
    
    @classmethod
    def highlight(cls, text: str) -> Tuple[str, List[EmailHighlight]]:
        """Highlight urgency manipulation"""
        highlights = []
        highlighted_text = text
        
        for severity, keywords in cls.URGENCY_KEYWORDS.items():
            for keyword in keywords:
                pattern = re.compile(re.escape(keyword), re.IGNORECASE)
                for match in pattern.finditer(text):
                    highlights.append(EmailHighlight(
                        element_type='urgency',
                        severity=severity,
                        start_pos=match.start(),
                        end_pos=match.end(),
                        original_text=match.group(),
                        explanation='This creates false urgency to pressure you into acting quickly',
                        suggested_action='Take time to verify - legitimate companies give you time to respond'
                    ))
        
        return highlighted_text, highlights


class AttachmentAnalyzer:
    """Analyzes email attachments for risks"""
    
    DANGEROUS_EXTENSIONS = {
        'executable': ['.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.msi'],
        'script': ['.js', '.vbs', '.wsf', '.ps1', '.sh', '.py'],
        'document_with_macros': ['.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm'],
        'archive': ['.zip', '.rar', '.7z', '.tar', '.gz'],
        'other': ['.lnk', '.dll', '.sys', '.inf']
    }
    
    @classmethod
    def analyze(cls, filename: str, file_size: int) -> Dict[str, str]:
        """Analyze attachment risk"""
        ext = '.' + filename.split('.')[-1].lower() if '.' in filename else ''
        
        risk_level = 'low'
        warning = None
        
        # Check dangerous extensions
        for category, extensions in cls.DANGEROUS_EXTENSIONS.items():
            if ext in extensions:
                if category == 'executable':
                    risk_level = 'critical'
                    warning = 'DANGER: Executable file - Never open from unknown senders'
                elif category == 'script':
                    risk_level = 'critical'
                    warning = 'DANGER: Script file - Can run malicious code'
                elif category == 'document_with_macros':
                    risk_level = 'high'
                    warning = 'WARNING: Can contain malicious macros - Scan before opening'
                elif category == 'archive':
                    risk_level = 'medium'
                    warning = 'CAUTION: Archive may contain malicious files - Scan contents'
                else:
                    risk_level = 'high'
                    warning = 'WARNING: Potentially dangerous file type'
                break
        
        # Check for double extensions (e.g., invoice.pdf.exe)
        if filename.count('.') > 1:
            risk_level = 'critical'
            warning = 'DANGER: Double extension detected - Common malware trick'
        
        # Check for very large files (potential zip bomb)
        if file_size > 50 * 1024 * 1024:  # 50MB
            risk_level = max(risk_level, 'medium')
            warning = warning or 'CAUTION: Very large file - Could be a zip bomb'
        
        return {
            'risk_level': risk_level,
            'warning': warning or 'File appears safe but always verify sender',
            'extension': ext,
            'size_mb': round(file_size / (1024 * 1024), 2)
        }


class SecureEmailViewer:
    """Main secure email viewer with threat highlighting"""
    
    def __init__(self):
        self.homoglyph_highlighter = HomoglyphHighlighter()
        self.link_highlighter = LinkHighlighter()
        self.urgency_detector = UrgencyDetector()
        self.attachment_analyzer = AttachmentAnalyzer()
    
    def render_safe(
        self,
        raw_html: str,
        subject: str,
        sender: str,
        attachments: Optional[List[Dict]] = None
    ) -> SafeEmail:
        """Render email safely with threat highlighting"""
        
        all_highlights = []
        
        # Step 1: Sanitize HTML (remove scripts, iframes, etc.)
        safe_html = self._sanitize_html(raw_html)
        
        # Step 2: Highlight homoglyphs in subject and body
        subject_text, subject_highlights = self.homoglyph_highlighter.highlight(subject)
        all_highlights.extend(subject_highlights)
        
        # Step 3: Highlight suspicious links
        safe_html, link_highlights = self.link_highlighter.highlight(safe_html)
        all_highlights.extend(link_highlights)
        
        # Step 4: Extract and highlight urgency keywords
        text_content = BeautifulSoup(safe_html, 'html.parser').get_text()
        _, urgency_highlights = self.urgency_detector.highlight(text_content)
        all_highlights.extend(urgency_highlights)
        
        # Step 5: Analyze attachments
        attachment_risks = {}
        has_dangerous_attachments = False
        
        if attachments:
            for att in attachments:
                filename = att.get('filename', 'unknown')
                size = att.get('size', 0)
                risk_info = self.attachment_analyzer.analyze(filename, size)
                attachment_risks[filename] = risk_info
                
                if risk_info['risk_level'] in ['critical', 'high']:
                    has_dangerous_attachments = True
                    
                    all_highlights.append(EmailHighlight(
                        element_type='dangerous_attachment',
                        severity=risk_info['risk_level'],
                        start_pos=0,
                        end_pos=0,
                        original_text=filename,
                        explanation=risk_info['warning'],
                        suggested_action='Open in sandbox or submit to admin for analysis'
                    ))
        
        # Step 6: Determine overall risk
        overall_risk = self._calculate_overall_risk(all_highlights, has_dangerous_attachments)
        
        # Step 7: Decide if safe to preview
        can_preview = overall_risk not in ['critical']
        
        # Step 8: Add CSS for highlighting
        safe_html = self._add_highlight_styles(safe_html)
        
        return SafeEmail(
            safe_html=safe_html,
            highlights=all_highlights,
            has_attachments=bool(attachments),
            attachment_risks=attachment_risks,
            overall_risk=overall_risk,
            can_preview=can_preview
        )
    
    @staticmethod
    def _sanitize_html(html_content: str) -> str:
        """Remove dangerous HTML elements"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Remove scripts
        for script in soup.find_all('script'):
            script.decompose()
        
        # Remove iframes
        for iframe in soup.find_all('iframe'):
            iframe.decompose()
        
        # Remove objects and embeds
        for obj in soup.find_all(['object', 'embed', 'applet']):
            obj.decompose()
        
        # Remove event handlers
        for tag in soup.find_all(True):
            for attr in list(tag.attrs.keys()):
                if attr.startswith('on'):  # onclick, onload, etc.
                    del tag[attr]
        
        # Remove form actions (prevent form submission)
        for form in soup.find_all('form'):
            form['action'] = '#'
            form['onsubmit'] = 'return false;'
        
        # Convert all links to open in new tab and show warning
        for link in soup.find_all('a', href=True):
            link['target'] = '_blank'
            link['rel'] = 'noopener noreferrer'
        
        return str(soup)
    
    @staticmethod
    def _calculate_overall_risk(highlights: List[EmailHighlight], has_dangerous_attachments: bool) -> str:
        """Calculate overall email risk"""
        if not highlights and not has_dangerous_attachments:
            return 'safe'
        
        # Count by severity
        critical_count = sum(1 for h in highlights if h.severity == 'critical')
        high_count = sum(1 for h in highlights if h.severity == 'high')
        
        if critical_count > 0 or has_dangerous_attachments:
            return 'critical'
        elif high_count > 2:
            return 'dangerous'
        elif high_count > 0:
            return 'suspicious'
        else:
            return 'low_risk'
    
    @staticmethod
    def _add_highlight_styles(html: str) -> str:
        """Add CSS styles for highlighting"""
        styles = """
        <style>
            .homoglyph-highlight {
                background-color: #fff3cd;
                border-bottom: 2px dotted #f59e0b;
                cursor: help;
                padding: 2px 4px;
                border-radius: 3px;
            }
            
            .suspicious-link {
                background-color: #fef2f2;
                border: 2px solid #ef4444;
                padding: 4px 8px;
                border-radius: 4px;
                position: relative;
                text-decoration: none;
            }
            
            .suspicious-link::before {
                content: '⚠️ ';
                font-weight: bold;
            }
            
            .link-mismatch {
                background-color: #7f1d1d;
                color: white;
            }
            
            .brand-impersonation {
                background-color: #991b1b;
                color: white;
                animation: pulse 2s infinite;
            }
            
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.7; }
            }
            
            .suspicious-tld {
                background-color: #fef2f2;
            }
        </style>
        """
        return styles + html


# Sandbox integration for safe attachment preview
class SandboxPreview:
    """Opens attachments in isolated sandbox environment"""
    
    @staticmethod
    def open_in_sandbox(file_path: str, file_type: str) -> Dict:
        """Open file in Docker sandbox for safe preview"""
        
        # In production: Launch Docker container with file
        # - Read-only file system
        # - No network access
        # - Resource limits
        # - Auto-destroy after 5 minutes
        
        sandbox_id = f"sandbox-{hash(file_path)}"
        
        return {
            "sandbox_id": sandbox_id,
            "status": "running",
            "url": f"http://localhost:8080/sandbox/{sandbox_id}",
            "expires_in": 300,  # 5 minutes
            "message": "File opened in isolated sandbox - safe to preview"
        }
    
    @staticmethod
    def create_safe_preview(file_content: bytes, filename: str) -> str:
        """Create safe preview without executing content"""
        
        ext = filename.split('.')[-1].lower()
        
        # Text files - show as plain text
        if ext in ['txt', 'log', 'csv']:
            try:
                text = file_content.decode('utf-8', errors='ignore')
                return f"<pre>{html.escape(text[:5000])}</pre>"  # Limit to 5000 chars
            except:
                return "<p>Unable to preview file</p>"
        
        # PDFs - show metadata only (don't render)
        elif ext == 'pdf':
            return """
            <div class="pdf-preview">
                <h3>PDF Document</h3>
                <p>⚠️ PDF preview disabled for security</p>
                <button onclick="downloadFile()">Download and scan with antivirus</button>
                <button onclick="openInSandbox()">Open in sandbox</button>
            </div>
            """
        
        # Images - use data URI with size limit
        elif ext in ['jpg', 'jpeg', 'png', 'gif']:
            if len(file_content) < 5 * 1024 * 1024:  # 5MB limit
                b64 = base64.b64encode(file_content).decode()
                return f'<img src="data:image/{ext};base64,{b64}" style="max-width:100%; max-height:500px;" />'
            else:
                return "<p>Image too large for preview</p>"
        
        # Everything else - no preview
        else:
            return f"""
            <div class="no-preview">
                <h3>File: {html.escape(filename)}</h3>
                <p>❌ Preview not available for security reasons</p>
                <button onclick="openInSandbox()">Open in Sandbox</button>
                <button onclick="submitToAdmin()">Submit to Admin</button>
            </div>
            """
