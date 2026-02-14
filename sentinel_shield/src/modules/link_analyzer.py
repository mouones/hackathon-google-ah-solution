"""
Sentinel Shield - Link Security Analyzer
Comprehensive URL and domain analysis for malicious link detection
"""

import re
import socket
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime, timedelta
import requests

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
    '.top', '.xyz', '.work', '.click', '.link',  # Cheap TLDs
    '.buzz', '.icu', '.monster', '.loan', '.download',
    '.zip', '.mov',  # New confusing TLDs
]

# URL Shorteners that hide real destinations
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'bc.vc', 'j.mp',
    'rb.gy', 'cutt.ly', 'shorturl.at', 'tiny.cc', 't.ly',
]

# Suspicious URL keywords
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure',
    'update', 'confirm', 'password', 'banking', 'support',
    'helpdesk', 'security', 'suspended', 'alert', 'notification',
]


@dataclass
class URLIndicator:
    """Represents a URL security indicator"""
    indicator_type: str
    severity: str  # critical, high, medium, low
    description: str
    score: int
    details: Dict = field(default_factory=dict)


@dataclass
class DomainInfo:
    """Domain intelligence data"""
    domain: str
    tld: str
    subdomain_count: int
    age_days: Optional[int] = None
    registrar: Optional[str] = None
    is_new: bool = False
    has_suspicious_tld: bool = False


@dataclass
class LinkAnalysis:
    """Complete link analysis result"""
    url: str
    is_malicious: bool
    threat_score: int  # 0-100
    threat_level: str  # safe, suspicious, dangerous, critical
    indicators: List[URLIndicator] = field(default_factory=list)
    domain_info: Optional[DomainInfo] = None
    final_url: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    virustotal_score: Optional[int] = None


class URLStructureAnalyzer:
    """Analyzes URL structure for suspicious patterns"""
    
    def analyze(self, url: str) -> List[URLIndicator]:
        """Analyze URL structure for suspicious elements"""
        indicators = []
        
        if not url:
            return indicators
        
        try:
            parsed = urlparse(url)
        except Exception:
            indicators.append(URLIndicator(
                indicator_type="malformed_url",
                severity="high",
                description="URL is malformed or cannot be parsed",
                score=30
            ))
            return indicators
        
        # 1. Check for IP address instead of domain
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, parsed.netloc):
            indicators.append(URLIndicator(
                indicator_type="ip_address_url",
                severity="critical",
                description="URL uses IP address instead of domain name",
                score=40,
                details={"ip": re.search(ip_pattern, parsed.netloc).group()}
            ))
        
        # 2. Check for @ symbol (used to hide real URL)
        if '@' in url:
            indicators.append(URLIndicator(
                indicator_type="at_symbol_obfuscation",
                severity="critical",
                description="URL contains @ symbol (hides real destination)",
                score=45,
                details={"technique": "credential_obfuscation"}
            ))
        
        # 3. Check URL length
        if len(url) > 200:
            indicators.append(URLIndicator(
                indicator_type="excessive_length",
                severity="low",
                description=f"URL is unusually long ({len(url)} characters)",
                score=10,
                details={"length": len(url)}
            ))
        
        # 4. Check for excessive hyphens in domain
        if parsed.netloc.count('-') > 3:
            indicators.append(URLIndicator(
                indicator_type="excessive_hyphens",
                severity="medium",
                description=f"Domain contains many hyphens ({parsed.netloc.count('-')})",
                score=15,
                details={"hyphen_count": parsed.netloc.count('-')}
            ))
        
        # 5. Check for suspicious keywords in URL
        url_lower = url.lower()
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
        if len(found_keywords) >= 2:
            indicators.append(URLIndicator(
                indicator_type="suspicious_keywords",
                severity="medium",
                description=f"URL contains suspicious keywords: {', '.join(found_keywords[:3])}",
                score=15,
                details={"keywords": found_keywords}
            ))
        
        # 6. Check for data URI scheme
        if url.lower().startswith('data:'):
            indicators.append(URLIndicator(
                indicator_type="data_uri",
                severity="critical",
                description="URL uses data: scheme (potential XSS/phishing)",
                score=50
            ))
        
        # 7. Check for javascript: scheme
        if url.lower().startswith('javascript:'):
            indicators.append(URLIndicator(
                indicator_type="javascript_uri",
                severity="critical",
                description="URL uses javascript: scheme (potential malicious script)",
                score=50
            ))
        
        # 8. Check for punycode/IDN (internationalized domain name)
        if 'xn--' in parsed.netloc.lower():
            indicators.append(URLIndicator(
                indicator_type="punycode_domain",
                severity="high",
                description="Domain uses Punycode (potential IDN homograph attack)",
                score=25,
                details={"punycode": parsed.netloc}
            ))
        
        # 9. Check for URL encoding obfuscation
        if '%' in url:
            decoded = unquote(url)
            if decoded.lower() != url.lower():
                # Check if decoded version reveals suspicious content
                encoded_count = url.count('%')
                if encoded_count > 10:
                    indicators.append(URLIndicator(
                        indicator_type="excessive_encoding",
                        severity="medium",
                        description=f"URL contains excessive encoding ({encoded_count} encoded chars)",
                        score=15,
                        details={"encoded_count": encoded_count}
                    ))
        
        # 10. Check for double extensions (file.pdf.exe)
        dangerous_extensions = ['.exe', '.scr', '.bat', '.cmd', '.js', '.vbs', '.ps1', '.msi']
        for ext in dangerous_extensions:
            if ext in url.lower() and not url.lower().endswith(ext):
                indicators.append(URLIndicator(
                    indicator_type="hidden_extension",
                    severity="high",
                    description=f"URL may contain hidden dangerous extension ({ext})",
                    score=30,
                    details={"extension": ext}
                ))
                break
        
        return indicators


class DomainAnalyzer:
    """Analyzes domain for security indicators"""
    
    def __init__(self):
        self.suspicious_tlds = SUSPICIOUS_TLDS
        self.url_shorteners = URL_SHORTENERS
    
    def analyze(self, url: str) -> Tuple[List[URLIndicator], DomainInfo]:
        """Analyze domain for suspicious patterns"""
        indicators = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Skip if IP address
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                return indicators, DomainInfo(domain=domain, tld="", subdomain_count=0)
            
        except Exception:
            return indicators, DomainInfo(domain="unknown", tld="", subdomain_count=0)
        
        # Parse domain parts
        parts = domain.split('.')
        if len(parts) < 2:
            return indicators, DomainInfo(domain=domain, tld="", subdomain_count=0)
        
        tld = '.' + parts[-1]
        subdomain_count = len(parts) - 2
        
        domain_info = DomainInfo(
            domain=domain,
            tld=tld,
            subdomain_count=subdomain_count
        )
        
        # 1. Check for suspicious TLD
        for suspicious_tld in self.suspicious_tlds:
            if domain.endswith(suspicious_tld):
                domain_info.has_suspicious_tld = True
                indicators.append(URLIndicator(
                    indicator_type="suspicious_tld",
                    severity="high",
                    description=f"Domain uses suspicious TLD: {suspicious_tld}",
                    score=25,
                    details={"tld": suspicious_tld}
                ))
                break
        
        # 2. Check for URL shortener
        for shortener in self.url_shorteners:
            if shortener in domain:
                indicators.append(URLIndicator(
                    indicator_type="url_shortener",
                    severity="medium",
                    description=f"URL uses shortening service: {shortener}",
                    score=15,
                    details={"shortener": shortener}
                ))
                break
        
        # 3. Check for excessive subdomains
        if subdomain_count > 3:
            indicators.append(URLIndicator(
                indicator_type="excessive_subdomains",
                severity="high",
                description=f"Domain has {subdomain_count} subdomain levels",
                score=20,
                details={"subdomain_count": subdomain_count}
            ))
        
        # 4. Check for brand impersonation in FULL domain (not just subdomain)
        brand_patterns = {
            'paypal': ['paypa1', 'paypaI', 'paypai', 'pаypal', 'раyраl', 'payp4l', 'paypall'],
            'microsoft': ['microsft', 'micr0soft', 'micrоsoft', 'rnicrosoft', 'micros0ft'],
            'apple': ['app1e', 'appIe', 'аpple', 'appie'],
            'google': ['g00gle', 'googIe', 'goog1e', 'gooogle', 'googel'],
            'amazon': ['amaz0n', 'аmazon', 'arnazon', 'amazоn'],
            'facebook': ['faceb00k', 'facebооk', 'facebok', 'fасebook'],
            'netflix': ['netf1ix', 'netfIix', 'netfiix', 'nettflix'],
            'bank': ['b4nk', 'bаnk'],
            'secure': ['secur3', 'sесure'],
        }
        
        # Check full domain for brand names and lookalikes
        full_domain_lower = domain.lower()
        for brand, lookalikes in brand_patterns.items():
            # Check for exact brand in non-official domain
            if brand in full_domain_lower and not full_domain_lower.endswith(f'{brand}.com'):
                indicators.append(URLIndicator(
                    indicator_type="brand_impersonation",
                    severity="critical",
                    description=f"Domain contains brand name '{brand}' (likely impersonation)",
                    score=40,
                    details={"brand": brand, "domain": domain}
                ))
                break
            # Check for homoglyph/lookalike patterns
            for lookalike in lookalikes:
                if lookalike in full_domain_lower:
                    indicators.append(URLIndicator(
                        indicator_type="homoglyph_attack",
                        severity="critical",
                        description=f"Homoglyph attack: '{lookalike}' looks like '{brand}'",
                        score=45,
                        details={"lookalike": lookalike, "brand": brand, "domain": domain}
                    ))
                    break
        
        # 5. Check subdomain for brand impersonation (already existing check, renumbered)
        if subdomain_count > 0:
            subdomain = '.'.join(parts[:-2])
            brand_keywords = ['paypal', 'microsoft', 'apple', 'google', 'amazon', 'bank', 'secure']
            for brand in brand_keywords:
                if brand in subdomain:
                    indicators.append(URLIndicator(
                        indicator_type="brand_in_subdomain",
                        severity="critical",
                        description=f"Brand name '{brand}' in subdomain (impersonation)",
                        score=35,
                        details={"brand": brand, "subdomain": subdomain}
                    ))
                    break
        
        # 6. Check domain age (via WHOIS simulation - in production use actual WHOIS)

        domain_age = self._estimate_domain_age(domain)
        if domain_age is not None:
            domain_info.age_days = domain_age
            if domain_age < 30:
                domain_info.is_new = True
                indicators.append(URLIndicator(
                    indicator_type="new_domain",
                    severity="high",
                    description=f"Domain is very new ({domain_age} days old)",
                    score=25,
                    details={"age_days": domain_age}
                ))
        
        return indicators, domain_info
    
    def _estimate_domain_age(self, domain: str) -> Optional[int]:
        """Estimate domain age (placeholder - use real WHOIS in production)"""
        # In production, use python-whois or similar
        try:
            import whois
            w = whois.whois(domain)
            if w.creation_date:
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                return (datetime.now() - creation).days
        except Exception:
            pass
        return None


class RedirectAnalyzer:
    """Analyzes URL redirect chains"""
    
    def __init__(self, timeout: int = 5, max_redirects: int = 10):
        self.timeout = timeout
        self.max_redirects = max_redirects
    
    def analyze(self, url: str) -> Tuple[List[URLIndicator], List[str], Optional[str]]:
        """Follow redirects and analyze chain"""
        indicators = []
        redirect_chain = [url]
        final_url = url
        
        try:
            session = requests.Session()
            session.max_redirects = self.max_redirects
            
            response = session.head(
                url,
                allow_redirects=True,
                timeout=self.timeout,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            # Build redirect chain
            if response.history:
                redirect_chain = [r.url for r in response.history] + [response.url]
                final_url = response.url
                
                # Check redirect count
                if len(response.history) > 2:
                    indicators.append(URLIndicator(
                        indicator_type="multiple_redirects",
                        severity="medium",
                        description=f"URL has {len(response.history)} redirects",
                        score=15,
                        details={"redirect_count": len(response.history)}
                    ))
                
                # Check for cross-domain redirect
                original_domain = urlparse(url).netloc
                final_domain = urlparse(final_url).netloc
                
                if original_domain != final_domain:
                    indicators.append(URLIndicator(
                        indicator_type="cross_domain_redirect",
                        severity="high",
                        description=f"URL redirects to different domain: {final_domain}",
                        score=25,
                        details={
                            "original_domain": original_domain,
                            "final_domain": final_domain
                        }
                    ))
        
        except requests.exceptions.TooManyRedirects:
            indicators.append(URLIndicator(
                indicator_type="redirect_loop",
                severity="high",
                description="URL causes redirect loop",
                score=30
            ))
        except requests.exceptions.Timeout:
            indicators.append(URLIndicator(
                indicator_type="timeout",
                severity="low",
                description="URL request timed out",
                score=5
            ))
        except Exception as e:
            pass  # Silent fail for network issues
        
        return indicators, redirect_chain, final_url


class VirusTotalIntegration:
    """Integration with VirusTotal API for URL scanning"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
    
    def scan_url(self, url: str) -> Optional[Dict]:
        """Scan URL with VirusTotal"""
        if not self.api_key:
            return None
        
        try:
            import base64
            
            # URL must be base64 encoded for VT API
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            headers = {"x-apikey": self.api_key}
            
            # Check existing report
            response = requests.get(
                f"{self.base_url}/urls/{url_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values())
                
                return {
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "total_scanners": total,
                    "score": int((malicious + suspicious * 0.5) / max(total, 1) * 100),
                    "detection_ratio": f"{malicious}/{total}"
                }
        
        except Exception as e:
            pass
        
        return None


class LinkSecurityAnalyzer:
    """Main link security analysis engine"""
    
    def __init__(self, virustotal_api_key: Optional[str] = None):
        self.structure_analyzer = URLStructureAnalyzer()
        self.domain_analyzer = DomainAnalyzer()
        self.redirect_analyzer = RedirectAnalyzer()
        self.virustotal = VirusTotalIntegration(virustotal_api_key)
    
    def analyze(self, url: str, check_redirects: bool = True, 
                check_virustotal: bool = True) -> LinkAnalysis:
        """Perform comprehensive link analysis"""
        
        all_indicators = []
        domain_info = None
        redirect_chain = []
        final_url = url
        vt_score = None
        
        # 1. Analyze URL structure
        structure_indicators = self.structure_analyzer.analyze(url)
        all_indicators.extend(structure_indicators)
        
        # 2. Analyze domain
        domain_indicators, domain_info = self.domain_analyzer.analyze(url)
        all_indicators.extend(domain_indicators)
        
        # 3. Check redirects
        if check_redirects:
            redirect_indicators, redirect_chain, final_url = self.redirect_analyzer.analyze(url)
            all_indicators.extend(redirect_indicators)
            
            # If redirected, analyze final URL too
            if final_url and final_url != url:
                final_structure = self.structure_analyzer.analyze(final_url)
                all_indicators.extend(final_structure)
        
        # 4. VirusTotal check
        if check_virustotal:
            vt_result = self.virustotal.scan_url(url)
            if vt_result:
                vt_score = vt_result['score']
                if vt_result['malicious_count'] > 0:
                    all_indicators.append(URLIndicator(
                        indicator_type="virustotal_detection",
                        severity="critical" if vt_result['malicious_count'] >= 3 else "high",
                        description=f"VirusTotal: {vt_result['detection_ratio']} engines flagged as malicious",
                        score=min(50, vt_result['malicious_count'] * 10),
                        details=vt_result
                    ))
        
        # Calculate total threat score
        total_score = min(100, sum(ind.score for ind in all_indicators))
        
        # Determine threat level
        if total_score >= 70:
            threat_level = "critical"
        elif total_score >= 50:
            threat_level = "dangerous"
        elif total_score >= 25:
            threat_level = "suspicious"
        else:
            threat_level = "safe"
        
        return LinkAnalysis(
            url=url,
            is_malicious=total_score >= 50,
            threat_score=total_score,
            threat_level=threat_level,
            indicators=all_indicators,
            domain_info=domain_info,
            final_url=final_url,
            redirect_chain=redirect_chain,
            virustotal_score=vt_score
        )
    
    def extract_urls(self, text: str) -> List[str]:
        """Extract all URLs from text"""
        url_pattern = r'https?://[^\s<>"{}|\\^\[\]`]+'
        return re.findall(url_pattern, text)
    
    def analyze_all(self, text: str) -> List[LinkAnalysis]:
        """Extract and analyze all URLs in text"""
        urls = self.extract_urls(text)
        return [self.analyze(url, check_redirects=False) for url in urls]


# Quick test
if __name__ == "__main__":
    analyzer = LinkSecurityAnalyzer()
    
    test_urls = [
        "https://microsoft-security-verify.tk/login.php",
        "https://bit.ly/3xyz123",
        "http://192.168.1.1/admin/login.php",
        "https://www.google.com/search?q=test",
        "https://login.paypal.secure-verify.suspicious-domain.ga/account",
        "https://docs.google.com/document/d/1234567890",
    ]
    
    print("=" * 60)
    print("🔗 SENTINEL SHIELD - LINK ANALYZER TEST")
    print("=" * 60)
    
    for url in test_urls:
        print(f"\n🌐 URL: {url[:60]}...")
        result = analyzer.analyze(url, check_redirects=False, check_virustotal=False)
        
        status = "🚨 MALICIOUS" if result.is_malicious else "✅ SAFE"
        print(f"   {status} | Score: {result.threat_score}/100 | Level: {result.threat_level}")
        
        if result.indicators:
            print(f"   Indicators ({len(result.indicators)}):")
            for ind in result.indicators[:3]:
                print(f"     - [{ind.severity.upper()}] {ind.description}")
        
        if result.domain_info:
            print(f"   Domain: {result.domain_info.domain} | TLD: {result.domain_info.tld}")
    
    print("\n" + "=" * 60)
