"""
Sentinel Shield - Suspicion Accumulator
Behavioral tracking system that replaces ineffective IP blocking
Tracks persistent patterns that survive IP rotation
"""

from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib
import re
from difflib import SequenceMatcher


@dataclass
class SuspicionSignal:
    """A single suspicion signal"""
    signal_type: str
    entity_type: str  # domain, sender, content, infrastructure
    entity_value: str
    score: int  # 1-100 contribution
    reason: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    ttl_hours: int = 168  # 7 days default


@dataclass 
class EntityProfile:
    """Accumulated profile for a tracked entity"""
    entity_type: str
    entity_value: str
    suspicion_score: int = 0
    signals: List[SuspicionSignal] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    occurrence_count: int = 0
    related_entities: Set[str] = field(default_factory=set)
    is_blocked: bool = False
    block_reason: Optional[str] = None


# Suspicion weights - what matters more
SUSPICION_WEIGHTS = {
    # Domain signals
    'domain_age_new': 30,           # < 7 days old
    'domain_age_very_new': 40,      # < 24 hours old
    'suspicious_tld': 25,           # .tk, .ml, .ga
    'free_subdomain': 20,           # blogspot, wordpress, etc
    'homoglyph_domain': 35,         # Contains lookalike chars
    'brand_in_subdomain': 40,       # paypal.evil.com pattern
    'excessive_hyphens': 15,        # many-hyphens-in-domain.com
    
    # Sender signals
    'new_sender': 10,               # First time seeing this sender
    'free_email_provider': 15,      # gmail, yahoo for business comms
    'display_name_mismatch': 25,    # Name doesn't match email
    'reply_to_mismatch': 30,        # Reply-to different domain
    
    # Content signals  
    'urgency_language': 20,         # URGENT, ACT NOW
    'sensitive_data_request': 30,   # Asks for password, SSN
    'suspicious_attachment': 35,    # .exe, .scr, macro-enabled
    'too_good_to_be_true': 25,      # You've won! Free money!
    'content_similarity': 20,       # Similar to known phishing
    
    # Infrastructure signals
    'bullet_proof_hosting': 40,     # Known bad hosting providers
    'newly_registered_ssl': 20,     # SSL cert < 30 days
    'mismatched_ssl_domain': 35,    # SSL doesn't match domain
    'unusual_port': 15,             # Non-standard ports
    
    # Behavioral signals
    'high_send_velocity': 30,       # Many emails in short time
    'targeting_executives': 25,     # Sent to C-level
    'outside_business_hours': 10,   # Sent at 3am local time
    'template_reuse': 25,           # Same template, different domain
}

# Thresholds for action
THRESHOLDS = {
    'monitor': 0,          # Score 0-30: Log and monitor
    'warning': 31,         # Score 31-50: Add warning banner
    'approval': 51,        # Score 51-70: Require approval
    'block': 71,           # Score 71+: Auto-block
    'critical': 90,        # Score 90+: Block + alert admin
}

# These persist across IP rotation - what we actually track
TRACKED_ENTITY_TYPES = [
    'domain',              # The sending domain
    'registrar',           # Domain registrar pattern
    'content_hash',        # Fuzzy hash of email content
    'sender_pattern',      # email pattern (not exact address)
    'link_pattern',        # URL structure pattern
    'asn',                 # Autonomous System Number
    'ssl_fingerprint',     # SSL certificate patterns
    'campaign_id',         # Clustered campaign identifier
]


class SuspicionAccumulator:
    """
    Behavioral tracking system that accumulates suspicion over time
    
    Key principle: Don't block IPs (they rotate). Track persistent patterns
    that survive across IP changes and campaign evolution.
    """
    
    def __init__(self):
        # Entity profiles storage
        self.profiles: Dict[str, EntityProfile] = {}
        
        # Cross-reference: entity -> related entities
        self.entity_graph: Dict[str, Set[str]] = defaultdict(set)
        
        # Campaign clustering
        self.campaigns: Dict[str, List[str]] = {}  # campaign_id -> [entities]
        
        # Known bad patterns
        self.known_bad_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.buzz', '.icu'}
        self.free_subdomains = {'blogspot', 'wordpress', '000webhostapp', 'weebly', 'wixsite', 'herokuapp'}
        self.free_email_providers = {'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com'}
        
        # Content fingerprints of known phishing
        self.known_phishing_fingerprints: Set[str] = set()
    
    def _get_entity_key(self, entity_type: str, entity_value: str) -> str:
        """Create unique key for entity"""
        return f"{entity_type}:{entity_value.lower()}"
    
    def _get_or_create_profile(self, entity_type: str, entity_value: str) -> EntityProfile:
        """Get existing profile or create new one"""
        key = self._get_entity_key(entity_type, entity_value)
        
        if key not in self.profiles:
            self.profiles[key] = EntityProfile(
                entity_type=entity_type,
                entity_value=entity_value.lower()
            )
        
        return self.profiles[key]
    
    def add_signal(self, entity_type: str, entity_value: str, 
                   signal_type: str, reason: str,
                   custom_score: Optional[int] = None) -> EntityProfile:
        """Add a suspicion signal to an entity"""
        
        profile = self._get_or_create_profile(entity_type, entity_value)
        
        # Get score from weights or use custom
        score = custom_score if custom_score else SUSPICION_WEIGHTS.get(signal_type, 10)
        
        signal = SuspicionSignal(
            signal_type=signal_type,
            entity_type=entity_type,
            entity_value=entity_value,
            score=score,
            reason=reason
        )
        
        profile.signals.append(signal)
        profile.last_seen = datetime.utcnow()
        profile.occurrence_count += 1
        
        # Recalculate total suspicion score
        self._recalculate_score(profile)
        
        return profile
    
    def _recalculate_score(self, profile: EntityProfile) -> int:
        """Recalculate suspicion score, decaying old signals"""
        
        now = datetime.utcnow()
        active_signals = []
        total_score = 0
        
        for signal in profile.signals:
            # Check if signal expired
            signal_age = now - signal.timestamp
            if signal_age.total_seconds() / 3600 > signal.ttl_hours:
                continue
            
            active_signals.append(signal)
            
            # Apply decay based on age
            decay = 1.0 - (signal_age.total_seconds() / (signal.ttl_hours * 3600))
            total_score += int(signal.score * decay)
        
        # Update profile
        profile.signals = active_signals
        profile.suspicion_score = min(100, total_score)
        
        # Auto-block if threshold exceeded
        if profile.suspicion_score >= THRESHOLDS['block'] and not profile.is_blocked:
            profile.is_blocked = True
            profile.block_reason = f"Suspicion score {profile.suspicion_score} exceeded threshold"
        
        return profile.suspicion_score
    
    def link_entities(self, entity1_type: str, entity1_value: str,
                      entity2_type: str, entity2_value: str) -> None:
        """Link two entities (they appeared together)"""
        
        key1 = self._get_entity_key(entity1_type, entity1_value)
        key2 = self._get_entity_key(entity2_type, entity2_value)
        
        self.entity_graph[key1].add(key2)
        self.entity_graph[key2].add(key1)
        
        # Also update profiles
        profile1 = self._get_or_create_profile(entity1_type, entity1_value)
        profile2 = self._get_or_create_profile(entity2_type, entity2_value)
        
        profile1.related_entities.add(key2)
        profile2.related_entities.add(key1)
    
    def get_inherited_suspicion(self, entity_type: str, entity_value: str) -> int:
        """Get suspicion inherited from related entities"""
        
        key = self._get_entity_key(entity_type, entity_value)
        related = self.entity_graph.get(key, set())
        
        if not related:
            return 0
        
        # Calculate average suspicion of related entities
        scores = []
        for related_key in related:
            if related_key in self.profiles:
                scores.append(self.profiles[related_key].suspicion_score)
        
        if not scores:
            return 0
        
        # Apply 50% inheritance factor
        return int(sum(scores) / len(scores) * 0.5)
    
    def analyze_domain(self, domain: str) -> List[SuspicionSignal]:
        """Analyze a domain and generate suspicion signals"""
        
        signals = []
        domain_lower = domain.lower()
        
        # Check TLD
        for tld in self.known_bad_tlds:
            if domain_lower.endswith(tld):
                signals.append(SuspicionSignal(
                    signal_type='suspicious_tld',
                    entity_type='domain',
                    entity_value=domain_lower,
                    score=SUSPICION_WEIGHTS['suspicious_tld'],
                    reason=f"Uses suspicious TLD: {tld}"
                ))
                break
        
        # Check free subdomain providers
        for subdomain in self.free_subdomains:
            if subdomain in domain_lower:
                signals.append(SuspicionSignal(
                    signal_type='free_subdomain',
                    entity_type='domain',
                    entity_value=domain_lower,
                    score=SUSPICION_WEIGHTS['free_subdomain'],
                    reason=f"Uses free hosting: {subdomain}"
                ))
                break
        
        # Check for excessive hyphens
        if domain_lower.count('-') > 3:
            signals.append(SuspicionSignal(
                signal_type='excessive_hyphens',
                entity_type='domain',
                entity_value=domain_lower,
                score=SUSPICION_WEIGHTS['excessive_hyphens'],
                reason=f"Excessive hyphens ({domain_lower.count('-')})"
            ))
        
        # Check for brand in subdomain pattern
        brands = ['paypal', 'microsoft', 'google', 'amazon', 'apple', 'netflix', 'bank']
        parts = domain_lower.split('.')
        if len(parts) > 2:
            subdomain_part = '.'.join(parts[:-2])
            for brand in brands:
                if brand in subdomain_part and brand not in parts[-2]:
                    signals.append(SuspicionSignal(
                        signal_type='brand_in_subdomain',
                        entity_type='domain',
                        entity_value=domain_lower,
                        score=SUSPICION_WEIGHTS['brand_in_subdomain'],
                        reason=f"Brand '{brand}' in subdomain (impersonation)"
                    ))
                    break
        
        return signals
    
    def analyze_sender(self, sender_email: str, display_name: str = "") -> List[SuspicionSignal]:
        """Analyze sender information"""
        
        signals = []
        
        if not sender_email:
            return signals
        
        sender_lower = sender_email.lower()
        domain = sender_lower.split('@')[-1] if '@' in sender_lower else ""
        
        # Check free email provider for business communication
        if domain in self.free_email_providers:
            signals.append(SuspicionSignal(
                signal_type='free_email_provider',
                entity_type='sender',
                entity_value=sender_lower,
                score=SUSPICION_WEIGHTS['free_email_provider'],
                reason=f"Uses free email provider: {domain}"
            ))
        
        # Check display name vs email mismatch
        if display_name:
            email_prefix = sender_lower.split('@')[0]
            display_lower = display_name.lower()
            
            # Check if display name looks like a brand but email doesn't match
            brands = ['paypal', 'microsoft', 'amazon', 'apple', 'google']
            for brand in brands:
                if brand in display_lower and brand not in domain:
                    signals.append(SuspicionSignal(
                        signal_type='display_name_mismatch',
                        entity_type='sender',
                        entity_value=sender_lower,
                        score=SUSPICION_WEIGHTS['display_name_mismatch'],
                        reason=f"Display name mentions '{brand}' but domain is {domain}"
                    ))
                    break
        
        return signals
    
    def analyze_content(self, content: str) -> Tuple[List[SuspicionSignal], str]:
        """Analyze email content, return signals and content fingerprint"""
        
        signals = []
        content_lower = content.lower()
        
        # Generate content fingerprint (fuzzy hash for similarity)
        fingerprint = self._content_fingerprint(content)
        
        # Check against known phishing fingerprints
        for known in self.known_phishing_fingerprints:
            similarity = SequenceMatcher(None, fingerprint, known).ratio()
            if similarity > 0.85:
                signals.append(SuspicionSignal(
                    signal_type='content_similarity',
                    entity_type='content_hash',
                    entity_value=fingerprint[:16],
                    score=SUSPICION_WEIGHTS['content_similarity'],
                    reason=f"Content {similarity:.0%} similar to known phishing"
                ))
                break
        
        # Check urgency language
        urgency_keywords = ['urgent', 'immediate', 'act now', 'expires today', 
                          'suspended', 'locked', 'verify now', 'final notice']
        found_urgency = [kw for kw in urgency_keywords if kw in content_lower]
        if len(found_urgency) >= 2:
            signals.append(SuspicionSignal(
                signal_type='urgency_language',
                entity_type='content_hash',
                entity_value=fingerprint[:16],
                score=SUSPICION_WEIGHTS['urgency_language'] * len(found_urgency),
                reason=f"Urgency language: {', '.join(found_urgency[:3])}"
            ))
        
        # Check for sensitive data requests
        sensitive_patterns = [
            (r'\b(password|passwd|pwd)\b', 'password'),
            (r'\b(ssn|social\s+security)\b', 'SSN'),
            (r'\b(credit\s+card|card\s+number|cvv)\b', 'credit card'),
            (r'\b(bank\s+account|routing\s+number)\b', 'bank account'),
        ]
        
        for pattern, data_type in sensitive_patterns:
            if re.search(pattern, content_lower):
                signals.append(SuspicionSignal(
                    signal_type='sensitive_data_request',
                    entity_type='content_hash',
                    entity_value=fingerprint[:16],
                    score=SUSPICION_WEIGHTS['sensitive_data_request'],
                    reason=f"Requests {data_type}"
                ))
                break
        
        return signals, fingerprint
    
    def _content_fingerprint(self, content: str) -> str:
        """Create fuzzy fingerprint of content for similarity matching"""
        
        # Normalize content
        normalized = content.lower()
        normalized = re.sub(r'\s+', ' ', normalized)
        normalized = re.sub(r'[^\w\s]', '', normalized)
        
        # Get word frequency distribution
        words = normalized.split()
        word_freq = defaultdict(int)
        for word in words:
            if len(word) > 3:  # Skip short words
                word_freq[word] += 1
        
        # Create fingerprint from top words
        top_words = sorted(word_freq.items(), key=lambda x: -x[1])[:20]
        fingerprint_data = '|'.join(w[0] for w in top_words)
        
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    def get_action_recommendation(self, entity_type: str, entity_value: str) -> Dict:
        """Get recommended action based on suspicion score"""
        
        profile = self._get_or_create_profile(entity_type, entity_value)
        score = profile.suspicion_score
        
        # Add inherited suspicion from related entities
        inherited = self.get_inherited_suspicion(entity_type, entity_value)
        effective_score = min(100, score + inherited)
        
        if effective_score >= THRESHOLDS['critical']:
            action = 'BLOCK_AND_ALERT'
            confidence = 'very_high'
        elif effective_score >= THRESHOLDS['block']:
            action = 'BLOCK'
            confidence = 'high'
        elif effective_score >= THRESHOLDS['approval']:
            action = 'REQUIRE_APPROVAL'
            confidence = 'medium'
        elif effective_score >= THRESHOLDS['warning']:
            action = 'ADD_WARNING'
            confidence = 'low'
        else:
            action = 'ALLOW'
            confidence = 'low'
        
        return {
            'action': action,
            'base_score': score,
            'inherited_score': inherited,
            'effective_score': effective_score,
            'confidence': confidence,
            'is_blocked': profile.is_blocked,
            'signal_count': len(profile.signals),
            'related_entities': len(profile.related_entities),
            'occurrence_count': profile.occurrence_count
        }
    
    def process_email(self, sender: str, sender_name: str, 
                      content: str, links: List[str] = None) -> Dict:
        """Process a complete email through suspicion analysis"""
        
        all_signals = []
        entities_analyzed = []
        
        # Analyze sender
        sender_signals = self.analyze_sender(sender, sender_name)
        all_signals.extend(sender_signals)
        
        # Add signals to sender profile
        for signal in sender_signals:
            self.add_signal(signal.entity_type, signal.entity_value,
                          signal.signal_type, signal.reason, signal.score)
            entities_analyzed.append(self._get_entity_key(signal.entity_type, signal.entity_value))
        
        # Analyze domain
        if '@' in sender:
            domain = sender.split('@')[-1]
            domain_signals = self.analyze_domain(domain)
            all_signals.extend(domain_signals)
            
            for signal in domain_signals:
                self.add_signal(signal.entity_type, signal.entity_value,
                              signal.signal_type, signal.reason, signal.score)
                entities_analyzed.append(self._get_entity_key('domain', domain))
            
            # Link sender to domain
            self.link_entities('sender', sender, 'domain', domain)
        
        # Analyze content
        content_signals, fingerprint = self.analyze_content(content)
        all_signals.extend(content_signals)
        
        for signal in content_signals:
            self.add_signal(signal.entity_type, signal.entity_value,
                          signal.signal_type, signal.reason, signal.score)
            entities_analyzed.append(self._get_entity_key('content_hash', fingerprint[:16]))
        
        # Analyze links if provided
        if links:
            for link in links:
                # Extract domain from link
                try:
                    from urllib.parse import urlparse
                    link_domain = urlparse(link).netloc
                    
                    link_signals = self.analyze_domain(link_domain)
                    all_signals.extend(link_signals)
                    
                    for signal in link_signals:
                        self.add_signal(signal.entity_type, signal.entity_value,
                                      signal.signal_type, signal.reason, signal.score)
                    
                    # Link email domain to link domain
                    if '@' in sender:
                        self.link_entities('domain', sender.split('@')[-1], 
                                         'domain', link_domain)
                except:
                    pass
        
        # Calculate overall recommendation
        max_score = 0
        for entity_key in set(entities_analyzed):
            if entity_key in self.profiles:
                score = self.profiles[entity_key].suspicion_score
                max_score = max(max_score, score)
        
        # Get action for highest scoring entity
        recommendation = self.get_action_recommendation('sender', sender) if '@' in sender else {
            'action': 'ALLOW',
            'effective_score': max_score
        }
        recommendation['total_signals'] = len(all_signals)
        recommendation['signals'] = [
            {
                'type': s.signal_type,
                'entity': s.entity_value[:30],
                'score': s.score,
                'reason': s.reason
            }
            for s in all_signals
        ]
        
        return recommendation


# Quick test
if __name__ == "__main__":
    accumulator = SuspicionAccumulator()
    
    print("=" * 60)
    print("🔍 SUSPICION ACCUMULATOR TEST")
    print("=" * 60)
    
    # Test 1: Suspicious email
    result = accumulator.process_email(
        sender="security@paypa1-verify.tk",
        sender_name="PayPal Security",
        content="URGENT: Your account has been suspended! Verify your password immediately or lose access forever!",
        links=["http://paypal.secure-login.tk/verify"]
    )
    
    print(f"\n📧 Test 1: Phishing email")
    print(f"   Action: {result['action']}")
    print(f"   Effective Score: {result['effective_score']}")
    print(f"   Signals: {result['total_signals']}")
    for sig in result['signals'][:3]:
        print(f"     - {sig['type']}: {sig['reason']}")
    
    # Test 2: Legitimate email
    result2 = accumulator.process_email(
        sender="john.doe@company.com",
        sender_name="John Doe",
        content="Hi team, here are the quarterly reports. Let me know if you have questions.",
        links=[]
    )
    
    print(f"\n📧 Test 2: Legitimate email")
    print(f"   Action: {result2['action']}")
    print(f"   Effective Score: {result2['effective_score']}")
    print(f"   Signals: {result2['total_signals']}")
    
    print("\n" + "=" * 60)
