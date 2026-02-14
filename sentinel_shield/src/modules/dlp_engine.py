"""
Sentinel Shield - Data Loss Prevention (DLP) Engine
Prevents unauthorized data exfiltration and enforces data policies
"""

import re
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import mimetypes


class DataClassification(Enum):
    """Data classification levels"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ActionType(Enum):
    """DLP action types"""
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    ENCRYPT = "encrypt"
    REDACT = "redact"
    ALERT = "alert"


@dataclass
class SensitivePattern:
    """Pattern for detecting sensitive data"""
    pattern_id: str
    name: str
    regex: str
    classification: DataClassification
    description: str
    sample_data: str = ""


@dataclass
class DLPMatch:
    """Represents a DLP policy match"""
    match_id: str
    pattern: SensitivePattern
    matched_data: str
    context: str
    position: int
    confidence: float
    redacted_value: str = ""


@dataclass
class DLPViolation:
    """Represents a DLP policy violation"""
    violation_id: str
    timestamp: datetime
    user: str
    action_attempted: str  # email, upload, print, copy
    destination: str
    matches: List[DLPMatch]
    severity: str
    action_taken: ActionType
    blocked: bool
    details: Dict = field(default_factory=dict)


@dataclass
class DLPPolicy:
    """DLP policy definition"""
    policy_id: str
    name: str
    description: str
    patterns: List[SensitivePattern]
    classification_level: DataClassification
    actions: Dict[str, ActionType]  # channel -> action
    exceptions: List[str] = field(default_factory=list)
    enabled: bool = True


class PatternLibrary:
    """Library of sensitive data patterns"""
    
    # Credit card patterns
    CREDIT_CARD_PATTERNS = [
        SensitivePattern(
            pattern_id="CC_VISA",
            name="Visa Credit Card",
            regex=r'\b4[0-9]{12}(?:[0-9]{3})?\b',
            classification=DataClassification.RESTRICTED,
            description="Visa credit card number",
            sample_data="4532-1234-5678-9010"
        ),
        SensitivePattern(
            pattern_id="CC_MASTERCARD",
            name="MasterCard",
            regex=r'\b5[1-5][0-9]{14}\b',
            classification=DataClassification.RESTRICTED,
            description="MasterCard credit card number",
            sample_data="5425-2334-3010-9372"
        ),
        SensitivePattern(
            pattern_id="CC_AMEX",
            name="American Express",
            regex=r'\b3[47][0-9]{13}\b',
            classification=DataClassification.RESTRICTED,
            description="American Express card number",
            sample_data="3782-822463-10005"
        ),
    ]
    
    # Social Security Number
    SSN_PATTERNS = [
        SensitivePattern(
            pattern_id="SSN_US",
            name="US Social Security Number",
            regex=r'\b\d{3}-\d{2}-\d{4}\b',
            classification=DataClassification.RESTRICTED,
            description="US SSN format",
            sample_data="123-45-6789"
        ),
        SensitivePattern(
            pattern_id="SSN_NO_DASH",
            name="SSN (no dashes)",
            regex=r'\b\d{9}\b',
            classification=DataClassification.RESTRICTED,
            description="SSN without separators",
            sample_data="123456789"
        ),
    ]
    
    # Passport numbers
    PASSPORT_PATTERNS = [
        SensitivePattern(
            pattern_id="PASSPORT_US",
            name="US Passport",
            regex=r'\b[0-9]{9}\b',
            classification=DataClassification.RESTRICTED,
            description="US passport number",
            sample_data="123456789"
        ),
    ]
    
    # Email addresses
    EMAIL_PATTERNS = [
        SensitivePattern(
            pattern_id="EMAIL_INTERNAL",
            name="Internal Email",
            regex=r'\b[a-zA-Z0-9._%+-]+@company\.com\b',
            classification=DataClassification.INTERNAL,
            description="Company internal email",
            sample_data="employee@company.com"
        ),
    ]
    
    # IP addresses
    IP_PATTERNS = [
        SensitivePattern(
            pattern_id="IP_PRIVATE",
            name="Private IP Address",
            regex=r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
            classification=DataClassification.INTERNAL,
            description="Private IP address",
            sample_data="192.168.1.100"
        ),
    ]
    
    # API keys and secrets
    SECRET_PATTERNS = [
        SensitivePattern(
            pattern_id="AWS_KEY",
            name="AWS Access Key",
            regex=r'\bAKIA[0-9A-Z]{16}\b',
            classification=DataClassification.RESTRICTED,
            description="AWS access key",
            sample_data="AKIAIOSFODNN7EXAMPLE"
        ),
        SensitivePattern(
            pattern_id="PRIVATE_KEY",
            name="Private Key",
            regex=r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
            classification=DataClassification.RESTRICTED,
            description="Private cryptographic key",
            sample_data="-----BEGIN PRIVATE KEY-----"
        ),
        SensitivePattern(
            pattern_id="GENERIC_API_KEY",
            name="Generic API Key",
            regex=r'\b[a-zA-Z0-9]{32,}\b',
            classification=DataClassification.CONFIDENTIAL,
            description="Generic API key pattern",
            sample_data="sk_live_51H7abcdefghijklmnop"
        ),
    ]
    
    # Healthcare
    HEALTHCARE_PATTERNS = [
        SensitivePattern(
            pattern_id="PHI_MRN",
            name="Medical Record Number",
            regex=r'\bMRN[:\s]?\d{6,10}\b',
            classification=DataClassification.RESTRICTED,
            description="Medical record number",
            sample_data="MRN: 1234567"
        ),
    ]


class DLPEngine:
    """Main DLP engine for data loss prevention"""
    
    def __init__(self):
        self.pattern_library = PatternLibrary()
        self.policies: Dict[str, DLPPolicy] = {}
        self.violations: List[DLPViolation] = []
        self.whitelist: Set[str] = set()
        
        # Initialize default policies
        self._initialize_default_policies()
    
    def _initialize_default_policies(self):
        """Create default DLP policies"""
        
        # Policy 1: Financial Data Protection
        self.policies['financial'] = DLPPolicy(
            policy_id='financial',
            name='Financial Data Protection',
            description='Prevents credit card and banking data leakage',
            patterns=self.pattern_library.CREDIT_CARD_PATTERNS,
            classification_level=DataClassification.RESTRICTED,
            actions={
                'email': ActionType.BLOCK,
                'upload': ActionType.BLOCK,
                'clipboard': ActionType.WARN,
                'print': ActionType.ALERT,
            },
            enabled=True
        )
        
        # Policy 2: PII Protection
        self.policies['pii'] = DLPPolicy(
            policy_id='pii',
            name='Personal Identifiable Information',
            description='Protects SSN, passport numbers, etc.',
            patterns=self.pattern_library.SSN_PATTERNS + self.pattern_library.PASSPORT_PATTERNS,
            classification_level=DataClassification.RESTRICTED,
            actions={
                'email': ActionType.BLOCK,
                'upload': ActionType.BLOCK,
                'clipboard': ActionType.REDACT,
                'print': ActionType.ALERT,
            },
            enabled=True
        )
        
        # Policy 3: Secrets Protection
        self.policies['secrets'] = DLPPolicy(
            policy_id='secrets',
            name='API Keys and Secrets',
            description='Prevents API keys and credentials leakage',
            patterns=self.pattern_library.SECRET_PATTERNS,
            classification_level=DataClassification.RESTRICTED,
            actions={
                'email': ActionType.BLOCK,
                'upload': ActionType.BLOCK,
                'clipboard': ActionType.WARN,
                'git': ActionType.BLOCK,
            },
            enabled=True
        )
        
        # Policy 4: Internal Data
        self.policies['internal'] = DLPPolicy(
            policy_id='internal',
            name='Internal Use Only',
            description='Monitors internal email and IP addresses',
            patterns=self.pattern_library.EMAIL_PATTERNS + self.pattern_library.IP_PATTERNS,
            classification_level=DataClassification.INTERNAL,
            actions={
                'email_external': ActionType.WARN,
                'upload_public': ActionType.WARN,
                'clipboard': ActionType.ALLOW,
            },
            enabled=True
        )
    
    def scan_content(self, content: str, context: str = "") -> List[DLPMatch]:
        """Scan content for sensitive data patterns"""
        matches = []
        
        # Scan with all enabled policies
        for policy in self.policies.values():
            if not policy.enabled:
                continue
            
            for pattern in policy.patterns:
                regex_matches = re.finditer(pattern.regex, content, re.IGNORECASE)
                
                for match in regex_matches:
                    matched_text = match.group()
                    
                    # Check whitelist
                    if self._is_whitelisted(matched_text):
                        continue
                    
                    # Validate match (e.g., Luhn algorithm for credit cards)
                    if not self._validate_match(pattern, matched_text):
                        continue
                    
                    # Extract context
                    start = max(0, match.start() - 20)
                    end = min(len(content), match.end() + 20)
                    match_context = content[start:end]
                    
                    # Create redacted version
                    redacted = self._redact_value(matched_text, pattern)
                    
                    dlp_match = DLPMatch(
                        match_id=f"MATCH-{datetime.now().timestamp()}",
                        pattern=pattern,
                        matched_data=matched_text,
                        context=match_context,
                        position=match.start(),
                        confidence=0.95,  # Could use ML for confidence
                        redacted_value=redacted
                    )
                    
                    matches.append(dlp_match)
        
        return matches
    
    def check_email(self, sender: str, recipients: List[str], 
                    subject: str, body: str, attachments: List[Dict] = None) -> DLPViolation:
        """Check email for DLP violations"""
        
        # Scan email body and subject
        all_content = f"{subject}\n\n{body}"
        matches = self.scan_content(all_content, context="email")
        
        # Determine if external recipients
        is_external = any(not r.endswith('@company.com') for r in recipients)
        
        # Determine action
        action_taken = ActionType.ALLOW
        blocked = False
        severity = "low"
        
        if matches:
            # Check highest classification
            highest_classification = max(
                m.pattern.classification.value for m in matches
            )
            
            if highest_classification == DataClassification.RESTRICTED.value:
                action_taken = ActionType.BLOCK
                blocked = True
                severity = "critical"
            elif highest_classification == DataClassification.CONFIDENTIAL.value and is_external:
                action_taken = ActionType.WARN
                severity = "high"
            else:
                action_taken = ActionType.ALERT
                severity = "medium"
        
        violation = DLPViolation(
            violation_id=f"VIO-{datetime.now().timestamp()}",
            timestamp=datetime.now(),
            user=sender,
            action_attempted="email",
            destination=", ".join(recipients),
            matches=matches,
            severity=severity,
            action_taken=action_taken,
            blocked=blocked,
            details={
                "subject": subject,
                "is_external": is_external,
                "attachment_count": len(attachments) if attachments else 0
            }
        )
        
        if blocked or action_taken != ActionType.ALLOW:
            self.violations.append(violation)
        
        return violation
    
    def check_file_upload(self, user: str, filename: str, 
                         content: bytes, destination_url: str) -> DLPViolation:
        """Check file upload for DLP violations"""
        
        # Try to decode content
        try:
            text_content = content.decode('utf-8', errors='ignore')
        except:
            text_content = ""
        
        matches = self.scan_content(text_content, context="file_upload")
        
        # Determine if upload is to external site
        is_external = not any(domain in destination_url for domain in ['company.com', 'localhost'])
        
        action_taken = ActionType.ALLOW
        blocked = False
        severity = "low"
        
        if matches:
            if any(m.pattern.classification == DataClassification.RESTRICTED for m in matches):
                action_taken = ActionType.BLOCK
                blocked = True
                severity = "critical"
            elif is_external:
                action_taken = ActionType.WARN
                severity = "high"
        
        violation = DLPViolation(
            violation_id=f"VIO-{datetime.now().timestamp()}",
            timestamp=datetime.now(),
            user=user,
            action_attempted="file_upload",
            destination=destination_url,
            matches=matches,
            severity=severity,
            action_taken=action_taken,
            blocked=blocked,
            details={
                "filename": filename,
                "file_size": len(content),
                "is_external": is_external
            }
        )
        
        if blocked or action_taken != ActionType.ALLOW:
            self.violations.append(violation)
        
        return violation
    
    def _validate_match(self, pattern: SensitivePattern, value: str) -> bool:
        """Validate matched value (e.g., Luhn check for credit cards)"""
        
        # Credit card validation using Luhn algorithm
        if pattern.pattern_id.startswith('CC_'):
            return self._luhn_check(value.replace('-', '').replace(' ', ''))
        
        # SSN validation (basic)
        if pattern.pattern_id.startswith('SSN_'):
            clean_ssn = value.replace('-', '')
            # Invalid SSN patterns
            if clean_ssn in ['000000000', '111111111', '123456789']:
                return False
            if clean_ssn.startswith('000') or clean_ssn.startswith('666'):
                return False
        
        return True
    
    def _luhn_check(self, card_number: str) -> bool:
        """Validate credit card using Luhn algorithm"""
        def digits_of(n):
            return [int(d) for d in str(n)]
        
        digits = digits_of(card_number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d * 2))
        return checksum % 10 == 0
    
    def _redact_value(self, value: str, pattern: SensitivePattern) -> str:
        """Redact sensitive value for logging"""
        if len(value) <= 4:
            return '****'
        
        # Show last 4 characters for credit cards/SSN
        if pattern.pattern_id.startswith(('CC_', 'SSN_')):
            return '****-****-****-' + value[-4:]
        
        # Show first and last character for others
        return value[0] + ('*' * (len(value) - 2)) + value[-1]
    
    def _is_whitelisted(self, value: str) -> bool:
        """Check if value is whitelisted"""
        value_hash = hashlib.sha256(value.encode()).hexdigest()
        return value_hash in self.whitelist
    
    def add_to_whitelist(self, value: str):
        """Add value to whitelist"""
        value_hash = hashlib.sha256(value.encode()).hexdigest()
        self.whitelist.add(value_hash)
    
    def get_violation_report(self, days: int = 7) -> Dict:
        """Generate violation report"""
        recent_violations = [
            v for v in self.violations
            if (datetime.now() - v.timestamp).days <= days
        ]
        
        return {
            "total_violations": len(recent_violations),
            "blocked_actions": len([v for v in recent_violations if v.blocked]),
            "by_severity": {
                "critical": len([v for v in recent_violations if v.severity == "critical"]),
                "high": len([v for v in recent_violations if v.severity == "high"]),
                "medium": len([v for v in recent_violations if v.severity == "medium"]),
                "low": len([v for v in recent_violations if v.severity == "low"]),
            },
            "by_action": {
                "email": len([v for v in recent_violations if v.action_attempted == "email"]),
                "upload": len([v for v in recent_violations if v.action_attempted == "file_upload"]),
            },
            "top_violators": self._get_top_violators(recent_violations),
        }
    
    def _get_top_violators(self, violations: List[DLPViolation], limit: int = 5) -> List[Dict]:
        """Get users with most violations"""
        user_counts = {}
        for v in violations:
            user_counts[v.user] = user_counts.get(v.user, 0) + 1
        
        sorted_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"user": user, "count": count} for user, count in sorted_users[:limit]]
