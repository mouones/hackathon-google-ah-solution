"""
Sentinel Shield - Phishing Detection Engine
Multi-model phishing detection with homoglyph analysis, NLP, and ML
"""

import re
import unicodedata
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import joblib

# Homoglyph mappings for character substitution detection
HOMOGLYPH_MAP = {
    # ASCII combinations that look like other letters
    'rn': 'm',
    'vv': 'w', 
    'cl': 'd',
    'nn': 'm',
    'ri': 'n',
    'lI': 'd',
    
    # Number to letter substitutions
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '8': 'b',
    
    # Cyrillic homoglyphs (Unicode)
    'а': 'a',  # Cyrillic a
    'е': 'e',  # Cyrillic e
    'о': 'o',  # Cyrillic o
    'р': 'p',  # Cyrillic r
    'с': 'c',  # Cyrillic c
    'у': 'y',  # Cyrillic u
    'х': 'x',  # Cyrillic x
    'і': 'i',  # Cyrillic i
    
    # Greek homoglyphs
    'ο': 'o',  # Greek omicron
    'α': 'a',  # Greek alpha
    'ρ': 'p',  # Greek rho
    'ν': 'v',  # Greek nu
    'τ': 't',  # Greek tau
    
    # Special characters
    'ı': 'i',  # Turkish dotless i
    'ł': 'l',  # Polish l with stroke
}

# Urgency keywords for phishing detection
URGENCY_KEYWORDS = {
    'critical': [
        'suspended', 'terminated', 'locked', 'blocked', 'disabled',
        'unauthorized', 'security breach', 'compromised', 'hacked',
        'illegal activity', 'criminal', 'law enforcement', 'arrest'
    ],
    'high': [
        'urgent', 'immediate', 'immediately', 'act now', 'expires today',
        'last chance', 'final notice', 'within 24 hours', 'within 48 hours',
        'limited time', 'today only', 'before it\'s too late'
    ],
    'medium': [
        'verify', 'confirm', 'update', 'validate', 'required action',
        'important', 'attention', 'alert', 'warning', 'notice'
    ]
}

# Protected brands database
PROTECTED_BRANDS = [
    # Tech Giants
    'microsoft', 'google', 'apple', 'amazon', 'meta', 'facebook',
    'netflix', 'spotify', 'twitter', 'linkedin', 'instagram', 'whatsapp',
    'paypal', 'ebay', 'dropbox', 'zoom', 'slack', 'adobe',
    
    # Banks and Financial
    'bankofamerica', 'chase', 'wellsfargo', 'citibank', 'hsbc',
    'barclays', 'santander', 'capitalone', 'usbank', 'tdbank',
    'venmo', 'cashapp', 'coinbase', 'binance',
    
    # Shipping and Logistics
    'fedex', 'ups', 'usps', 'dhl', 'amazon',
    
    # Government
    'irs', 'ssa', 'dmv', 'uscis', 'medicare',
    
    # Telecom
    'verizon', 'att', 'tmobile', 'sprint', 'comcast',
]


@dataclass
class HomoglyphMatch:
    """Represents a detected homoglyph attack"""
    pattern: str
    looks_like: str
    position: int
    context: str
    script: str = "ascii"
    
    
@dataclass
class PhishingIndicator:
    """Represents a phishing indicator"""
    indicator_type: str
    severity: str  # critical, high, medium, low
    description: str
    score: int
    details: Dict = field(default_factory=dict)


@dataclass
class PhishingAnalysis:
    """Complete phishing analysis result"""
    is_phishing: bool
    threat_score: int  # 0-100
    confidence: float  # 0.0-1.0
    indicators: List[PhishingIndicator] = field(default_factory=list)
    homoglyphs: List[HomoglyphMatch] = field(default_factory=list)
    brand_impersonation: Optional[str] = None
    recommendation: str = ""


class HomoglyphDetector:
    """Detects homoglyph/character substitution attacks"""
    
    def __init__(self):
        self.homoglyph_map = HOMOGLYPH_MAP
        self.protected_brands = PROTECTED_BRANDS
        
    def detect(self, text: str) -> List[HomoglyphMatch]:
        """Detect all homoglyphs in text"""
        matches = []
        
        if not text:
            return matches
        
        text_lower = text.lower()
        
        # Check ASCII substitution patterns (rn -> m, vv -> w)
        for pattern, looks_like in self.homoglyph_map.items():
            if len(pattern) > 1:  # Multi-character patterns
                idx = 0
                while True:
                    idx = text_lower.find(pattern, idx)
                    if idx == -1:
                        break
                    
                    context_start = max(0, idx - 10)
                    context_end = min(len(text), idx + len(pattern) + 10)
                    context = text[context_start:context_end]
                    
                    matches.append(HomoglyphMatch(
                        pattern=pattern,
                        looks_like=looks_like,
                        position=idx,
                        context=context,
                        script="ascii"
                    ))
                    idx += 1
        
        # Check Unicode homoglyphs
        for i, char in enumerate(text):
            if char in self.homoglyph_map:
                looks_like = self.homoglyph_map[char]
                if len(looks_like) == 1:  # Single character substitution
                    # Determine script
                    char_name = unicodedata.name(char, "UNKNOWN")
                    if "CYRILLIC" in char_name:
                        script = "cyrillic"
                    elif "GREEK" in char_name:
                        script = "greek"
                    else:
                        script = "special"
                    
                    context_start = max(0, i - 10)
                    context_end = min(len(text), i + 11)
                    context = text[context_start:context_end]
                    
                    matches.append(HomoglyphMatch(
                        pattern=char,
                        looks_like=looks_like,
                        position=i,
                        context=context,
                        script=script
                    ))
        
        return matches
    
    def detect_brand_impersonation(self, domain: str) -> Optional[Tuple[str, float]]:
        """Check if domain impersonates a known brand"""
        if not domain:
            return None
        
        domain_lower = domain.lower()
        
        # Remove common TLDs for comparison
        domain_parts = domain_lower.split('.')
        domain_name = domain_parts[0] if domain_parts else domain_lower
        
        for brand in self.protected_brands:
            # Exact match (official domain)
            if domain_name == brand:
                continue  # This might be legitimate
            
            # Check for brand with substitutions
            normalized_domain = self._normalize_homoglyphs(domain_name)
            
            if brand in normalized_domain:
                # Calculate similarity
                similarity = self._calculate_similarity(brand, normalized_domain)
                if similarity > 0.7:
                    return (brand, similarity)
            
            # Check for typosquatting
            if self._is_typosquat(domain_name, brand):
                return (brand, 0.85)
        
        return None
    
    def _normalize_homoglyphs(self, text: str) -> str:
        """Replace homoglyphs with their ASCII equivalents"""
        result = text.lower()
        
        # Apply multi-character substitutions first
        result = result.replace('rn', 'm').replace('vv', 'w').replace('cl', 'd')
        
        # Apply single-character substitutions
        for pattern, replacement in self.homoglyph_map.items():
            if len(pattern) == 1 and len(replacement) == 1:
                result = result.replace(pattern, replacement)
        
        return result
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate string similarity using Levenshtein distance"""
        from difflib import SequenceMatcher
        return SequenceMatcher(None, str1, str2).ratio()
    
    def _is_typosquat(self, domain: str, brand: str) -> bool:
        """Check for common typosquatting patterns"""
        # Missing character
        for i in range(len(brand)):
            if domain == brand[:i] + brand[i+1:]:
                return True
        
        # Extra character
        for i in range(len(domain)):
            if brand == domain[:i] + domain[i+1:]:
                return True
        
        # Swapped characters
        for i in range(len(brand) - 1):
            swapped = brand[:i] + brand[i+1] + brand[i] + brand[i+2:]
            if domain == swapped:
                return True
        
        # Common misspellings
        if self._calculate_similarity(domain, brand) > 0.85:
            return True
        
        return False


class UrgencyAnalyzer:
    """Analyzes text for urgency and manipulation patterns"""
    
    def __init__(self):
        self.urgency_keywords = URGENCY_KEYWORDS
    
    def analyze(self, text: str) -> List[PhishingIndicator]:
        """Analyze text for urgency indicators"""
        indicators = []
        
        if not text:
            return indicators
        
        text_lower = text.lower()
        
        # Check for urgency keywords by severity
        for severity, keywords in self.urgency_keywords.items():
            found_keywords = []
            for keyword in keywords:
                if keyword in text_lower:
                    found_keywords.append(keyword)
            
            if found_keywords:
                score_map = {'critical': 30, 'high': 20, 'medium': 10}
                indicators.append(PhishingIndicator(
                    indicator_type="urgency_language",
                    severity=severity,
                    description=f"Contains {severity} urgency keywords: {', '.join(found_keywords[:3])}",
                    score=score_map.get(severity, 10) * len(found_keywords),
                    details={"keywords": found_keywords}
                ))
        
        # Check for excessive capitalization
        caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        if caps_ratio > 0.3:
            indicators.append(PhishingIndicator(
                indicator_type="excessive_caps",
                severity="medium",
                description=f"Excessive capitalization ({caps_ratio:.0%} uppercase)",
                score=15,
                details={"caps_ratio": caps_ratio}
            ))
        
        # Check for excessive punctuation
        exclaim_count = text.count('!')
        question_count = text.count('?')
        if exclaim_count > 3 or question_count > 3:
            indicators.append(PhishingIndicator(
                indicator_type="excessive_punctuation",
                severity="low",
                description=f"Excessive punctuation (! = {exclaim_count}, ? = {question_count})",
                score=10,
                details={"exclamations": exclaim_count, "questions": question_count}
            ))
        
        return indicators


class EmailFormalityAnalyzer:
    """Analyzes email formality and professionalism"""
    
    def analyze(self, text: str, sender_name: str = "", signature_name: str = "") -> List[PhishingIndicator]:
        """Analyze email formality"""
        indicators = []
        
        if not text:
            return indicators
        
        text_lower = text.lower()
        
        # Check for informal greetings
        informal_greetings = ['hey', 'yo', 'sup', 'hiya', 'heya']
        for greeting in informal_greetings:
            if text_lower.startswith(greeting):
                indicators.append(PhishingIndicator(
                    indicator_type="informal_greeting",
                    severity="low",
                    description=f"Informal greeting detected: {greeting}",
                    score=5
                ))
                break
        
        # Check for grammar issues (basic patterns)
        grammar_issues = [
            (r'\bi\b', "lowercase 'I'"),
            (r'\bu\b', "'u' instead of 'you'"),
            (r'\bur\b', "'ur' instead of 'your'"),
            (r'\bgonna\b', "'gonna' instead of 'going to'"),
            (r'\bwanna\b', "'wanna' instead of 'want to'"),
        ]
        
        for pattern, description in grammar_issues:
            if re.search(pattern, text_lower):
                indicators.append(PhishingIndicator(
                    indicator_type="grammar_issue",
                    severity="low",
                    description=f"Informal language: {description}",
                    score=5
                ))
        
        # Check for name mismatch
        if sender_name and signature_name:
            if self._names_mismatch(sender_name, signature_name):
                indicators.append(PhishingIndicator(
                    indicator_type="name_mismatch",
                    severity="high",
                    description=f"Sender name '{sender_name}' doesn't match signature '{signature_name}'",
                    score=25,
                    details={
                        "sender_name": sender_name,
                        "signature_name": signature_name
                    }
                ))
        
        return indicators
    
    def _names_mismatch(self, name1: str, name2: str) -> bool:
        """Check if two names are significantly different"""
        from difflib import SequenceMatcher
        
        name1_parts = name1.lower().split()
        name2_parts = name2.lower().split()
        
        # Check for any matching parts
        for part1 in name1_parts:
            for part2 in name2_parts:
                if SequenceMatcher(None, part1, part2).ratio() > 0.8:
                    return False
        
        return True


class SensitiveDataDetector:
    """Detects requests for sensitive data"""
    
    SENSITIVE_PATTERNS = {
        'password': (r'\b(password|passwd|pwd|passcode)\b', 30),
        'ssn': (r'\b(ssn|social\s+security\s+(number)?)\b', 40),
        'credit_card': (r'\b(credit\s+card|card\s+number|cvv|ccv|cvc)\b', 35),
        'bank_account': (r'\b(bank\s+account|routing\s+number|account\s+number)\b', 35),
        'pin': (r'\b(pin\s+(number|code)?)\b', 30),
        'security_code': (r'\b(security\s+(code|question)|mother\'?s?\s+maiden)\b', 25),
        'login': (r'\b(login|log\s+in|sign\s+in|username)\b', 15),
    }
    
    def detect(self, text: str) -> List[PhishingIndicator]:
        """Detect requests for sensitive information"""
        indicators = []
        
        if not text:
            return indicators
        
        text_lower = text.lower()
        
        for data_type, (pattern, score) in self.SENSITIVE_PATTERNS.items():
            if re.search(pattern, text_lower, re.IGNORECASE):
                indicators.append(PhishingIndicator(
                    indicator_type="sensitive_data_request",
                    severity="high" if score >= 30 else "medium",
                    description=f"Requests sensitive data: {data_type.replace('_', ' ')}",
                    score=score,
                    details={"data_type": data_type}
                ))
        
        return indicators


class PhishingDetector:
    """Main phishing detection engine combining all analyzers"""
    
    def __init__(self, model_path: Optional[str] = None):
        self.homoglyph_detector = HomoglyphDetector()
        self.urgency_analyzer = UrgencyAnalyzer()
        self.formality_analyzer = EmailFormalityAnalyzer()
        self.sensitive_detector = SensitiveDataDetector()
        self.ml_model = None
        self.ml_vectorizer = None
        self.ml_scaler = None
        
        if model_path:
            self.load_ml_model(model_path)
    
    def load_ml_model(self, path: str) -> bool:
        """Load trained ML model"""
        try:
            data = joblib.load(path)
            self.ml_model = data.get('model')
            self.ml_vectorizer = data.get('text_vectorizer')
            self.ml_scaler = data.get('feature_scaler')
            return True
        except Exception as e:
            print(f"Failed to load ML model: {e}")
            return False
    
    def analyze(self, 
                text: str,
                sender_email: str = "",
                sender_name: str = "",
                subject: str = "") -> PhishingAnalysis:
        """Perform comprehensive phishing analysis"""
        
        indicators: List[PhishingIndicator] = []
        homoglyphs: List[HomoglyphMatch] = []
        brand_impersonation = None
        
        # Combine text for analysis
        full_text = f"{subject} {text}"
        
        # 1. Homoglyph detection
        homoglyphs = self.homoglyph_detector.detect(full_text)
        if homoglyphs:
            indicators.append(PhishingIndicator(
                indicator_type="homoglyph_attack",
                severity="high",
                description=f"Detected {len(homoglyphs)} character substitution(s)",
                score=15 * len(homoglyphs),
                details={"count": len(homoglyphs)}
            ))
        
        # 2. Brand impersonation in sender email
        if sender_email:
            domain = sender_email.split('@')[-1] if '@' in sender_email else sender_email
            brand_check = self.homoglyph_detector.detect_brand_impersonation(domain)
            if brand_check:
                brand_impersonation = brand_check[0]
                indicators.append(PhishingIndicator(
                    indicator_type="brand_impersonation",
                    severity="critical",
                    description=f"Impersonating {brand_check[0]} (similarity: {brand_check[1]:.0%})",
                    score=40,
                    details={"brand": brand_check[0], "similarity": brand_check[1]}
                ))
        
        # 3. Urgency analysis
        indicators.extend(self.urgency_analyzer.analyze(full_text))
        
        # 4. Formality analysis
        indicators.extend(self.formality_analyzer.analyze(text, sender_name, ""))
        
        # 5. Sensitive data requests
        indicators.extend(self.sensitive_detector.detect(full_text))
        
        # 6. ML model prediction (if available)
        ml_score = 0
        if self.ml_model:
            try:
                ml_result = self._ml_predict(full_text)
                ml_score = int(ml_result.get('confidence', 0) * 100)
                if ml_result.get('is_phishing'):
                    indicators.append(PhishingIndicator(
                        indicator_type="ml_prediction",
                        severity="high" if ml_score > 70 else "medium",
                        description=f"ML model predicts phishing ({ml_score}% confidence)",
                        score=ml_score // 2,  # Contribute up to 50 points
                        details={"confidence": ml_score}
                    ))
            except Exception:
                pass
        
        # Calculate total threat score
        total_score = min(100, sum(ind.score for ind in indicators))
        
        # Determine if phishing and confidence
        is_phishing = total_score >= 50
        confidence = min(1.0, total_score / 100 + 0.1) if is_phishing else max(0.0, 1.0 - (total_score / 100))
        
        # Generate recommendation
        if total_score >= 80:
            recommendation = "BLOCK_IMMEDIATE"
        elif total_score >= 60:
            recommendation = "QUARANTINE"
        elif total_score >= 40:
            recommendation = "WARN_USER"
        elif total_score >= 20:
            recommendation = "FLAG_FOR_REVIEW"
        else:
            recommendation = "ALLOW"
        
        return PhishingAnalysis(
            is_phishing=is_phishing,
            threat_score=total_score,
            confidence=confidence,
            indicators=indicators,
            homoglyphs=homoglyphs,
            brand_impersonation=brand_impersonation,
            recommendation=recommendation
        )
    
    def _ml_predict(self, text: str) -> Dict:
        """Make prediction using ML model"""
        if not self.ml_model or not self.ml_vectorizer:
            return {"is_phishing": False, "confidence": 0}
        
        import scipy.sparse as sp
        import numpy as np
        
        # Vectorize text
        text_features = self.ml_vectorizer.transform([text])
        
        # Create dummy numerical features
        numerical_features = np.zeros((1, 8))  # Placeholder
        if self.ml_scaler:
            numerical_features = self.ml_scaler.transform(numerical_features)
        
        # Combine features
        combined = sp.hstack([text_features, numerical_features])
        
        # Predict
        prediction = self.ml_model.predict(combined)[0]
        probability = self.ml_model.predict_proba(combined)[0]
        
        return {
            "is_phishing": bool(prediction),
            "confidence": float(probability[1])
        }


# Quick test
if __name__ == "__main__":
    detector = PhishingDetector()
    
    # Test cases
    test_emails = [
        {
            "text": "URGENT: Your Micros0ft account has been suspended! Click here to verify immediately or lose access forever!",
            "sender_email": "security@rnicrosoft-support.tk",
            "sender_name": "Microsoft Security",
            "subject": "Account Suspended - Action Required NOW!"
        },
        {
            "text": "Hi team, here are the quarterly reports you requested. Let me know if you have any questions.",
            "sender_email": "sarah.jones@company.com",
            "sender_name": "Sarah Jones",
            "subject": "Q4 Reports"
        },
        {
            "text": "Dear valued customer, you've won $1,000,000! Send your bank account details to claim your prize!",
            "sender_email": "winner@lottery-claim.ga",
            "sender_name": "Prize Department",
            "subject": "You've Won! Claim Now!"
        }
    ]
    
    print("=" * 60)
    print("🛡️  SENTINEL SHIELD - PHISHING DETECTOR TEST")
    print("=" * 60)
    
    for i, email in enumerate(test_emails, 1):
        print(f"\n📧 Test Email #{i}")
        print(f"   Subject: {email['subject'][:50]}...")
        
        result = detector.analyze(
            text=email['text'],
            sender_email=email['sender_email'],
            sender_name=email['sender_name'],
            subject=email['subject']
        )
        
        status = "🚨 PHISHING" if result.is_phishing else "✅ SAFE"
        print(f"   {status} | Score: {result.threat_score}/100 | Confidence: {result.confidence:.0%}")
        print(f"   Recommendation: {result.recommendation}")
        
        if result.indicators:
            print(f"   Indicators ({len(result.indicators)}):")
            for ind in result.indicators[:3]:
                print(f"     - [{ind.severity.upper()}] {ind.description}")
        
        if result.brand_impersonation:
            print(f"   ⚠️  Brand Impersonation: {result.brand_impersonation}")
    
    print("\n" + "=" * 60)
