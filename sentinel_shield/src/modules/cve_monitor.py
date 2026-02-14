"""
Sentinel Shield - CVE Vulnerability Monitor
Monitors frameworks and dependencies for known vulnerabilities
Provides automated alerts and patch recommendations
"""

import requests
import json
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import re
from packaging import version
import subprocess


@dataclass
class Vulnerability:
    """Represents a CVE vulnerability"""
    cve_id: str
    severity: str  # critical, high, medium, low
    cvss_score: float
    description: str
    affected_products: List[str]
    affected_versions: List[str]
    fixed_version: Optional[str] = None
    published_date: datetime = field(default_factory=datetime.now)
    exploit_available: bool = False
    references: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None


@dataclass
class DependencyInfo:
    """Information about a dependency"""
    name: str
    current_version: str
    latest_version: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    risk_score: int = 0
    update_available: bool = False


@dataclass
class CVEAlert:
    """CVE alert for monitoring system"""
    alert_id: str
    vulnerability: Vulnerability
    affected_dependencies: List[str]
    severity_level: str
    recommended_action: str
    sla_deadline: datetime
    acknowledged: bool = False
    patched: bool = False


class CVEMonitor:
    """Main CVE monitoring engine"""
    
    def __init__(self):
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.osv_api_url = "https://api.osv.dev/v1"
        self.github_advisory_url = "https://api.github.com/advisories"
        self.snyk_api_url = "https://snyk.io/api/v1"
        
        # Cache of known vulnerabilities
        self.vulnerability_cache: Dict[str, Vulnerability] = {}
        
        # Monitored products/frameworks
        self.monitored_products = self._initialize_monitored_products()
        
        # Severity thresholds for alerts
        self.severity_thresholds = {
            'critical': (9.0, 10.0, timedelta(hours=0)),  # Immediate
            'high': (7.0, 8.9, timedelta(hours=24)),
            'medium': (4.0, 6.9, timedelta(days=7)),
            'low': (0.1, 3.9, timedelta(days=30))
        }
    
    def _initialize_monitored_products(self) -> Set[str]:
        """Initialize list of products to monitor"""
        return {
            # Python ecosystem
            'python', 'django', 'flask', 'fastapi', 'requests', 'sqlalchemy',
            'numpy', 'pandas', 'pillow', 'cryptography', 'pyjwt',
            
            # JavaScript/Node ecosystem
            'node.js', 'express', 'react', 'vue', 'angular', 'webpack',
            'lodash', 'axios', 'socket.io',
            
            # Database systems
            'postgresql', 'mysql', 'mongodb', 'redis', 'elasticsearch',
            
            # Web servers
            'nginx', 'apache', 'tomcat', 'iis',
            
            # Security tools
            'openssl', 'openssh', 'docker', 'kubernetes',
            
            # Operating systems
            'windows server', 'ubuntu', 'centos', 'debian'
        }
    
    def check_nvd_for_vulnerabilities(self, product: str, version_str: str = None) -> List[Vulnerability]:
        """Check NVD (National Vulnerability Database) for CVEs"""
        vulnerabilities = []
        
        try:
            params = {
                'keyword': product,
                'resultsPerPage': 20
            }
            
            response = requests.get(self.nvd_api_url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                for vuln_data in data.get('vulnerabilities', []):
                    cve_item = vuln_data.get('cve', {})
                    
                    # Extract CVSS score
                    cvss_score = 0.0
                    metrics = cve_item.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV30' in metrics:
                        cvss_score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                    
                    # Determine severity
                    severity = self._get_severity_from_cvss(cvss_score)
                    
                    # Extract description
                    descriptions = cve_item.get('descriptions', [])
                    description = descriptions[0].get('value', '') if descriptions else ''
                    
                    # Create vulnerability object
                    vulnerability = Vulnerability(
                        cve_id=cve_item.get('id', ''),
                        severity=severity,
                        cvss_score=cvss_score,
                        description=description,
                        affected_products=[product],
                        affected_versions=[],
                        published_date=datetime.fromisoformat(
                            cve_item.get('published', '').replace('Z', '+00:00')
                        ) if 'published' in cve_item else datetime.now()
                    )
                    
                    vulnerabilities.append(vulnerability)
                    self.vulnerability_cache[vulnerability.cve_id] = vulnerability
            
        except Exception as e:
            print(f"Error checking NVD: {e}")
        
        return vulnerabilities
    
    def check_osv_for_vulnerabilities(self, package_name: str, version_str: str) -> List[Vulnerability]:
        """Check OSV (Open Source Vulnerabilities) database"""
        vulnerabilities = []
        
        try:
            payload = {
                "package": {
                    "name": package_name
                },
                "version": version_str
            }
            
            response = requests.post(
                f"{self.osv_api_url}/query",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                for vuln_data in data.get('vulns', []):
                    # Extract severity
                    severity_ratings = vuln_data.get('severity', [])
                    cvss_score = 0.0
                    
                    if severity_ratings:
                        score_str = severity_ratings[0].get('score', '')
                        if score_str:
                            cvss_score = float(score_str.split(':')[-1]) if ':' in score_str else 0.0
                    
                    severity = self._get_severity_from_cvss(cvss_score)
                    
                    vulnerability = Vulnerability(
                        cve_id=vuln_data.get('id', ''),
                        severity=severity,
                        cvss_score=cvss_score,
                        description=vuln_data.get('summary', ''),
                        affected_products=[package_name],
                        affected_versions=vuln_data.get('affected', []),
                        references=[ref.get('url', '') for ref in vuln_data.get('references', [])]
                    )
                    
                    vulnerabilities.append(vulnerability)
                    
        except Exception as e:
            print(f"Error checking OSV: {e}")
        
        return vulnerabilities
    
    def scan_python_dependencies(self, requirements_file: str = "requirements.txt") -> List[DependencyInfo]:
        """Scan Python dependencies for vulnerabilities"""
        dependencies = []
        
        try:
            # Read requirements file
            with open(requirements_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse package name and version
                    match = re.match(r'([a-zA-Z0-9_-]+)==([0-9.]+)', line)
                    if match:
                        package_name = match.group(1)
                        current_version = match.group(2)
                        
                        # Check for vulnerabilities
                        vulnerabilities = self.check_osv_for_vulnerabilities(
                            package_name.lower(),
                            current_version
                        )
                        
                        # Get latest version (simulated)
                        latest_version = self._get_latest_version(package_name)
                        
                        # Calculate risk score
                        risk_score = self._calculate_risk_score(vulnerabilities)
                        
                        dep_info = DependencyInfo(
                            name=package_name,
                            current_version=current_version,
                            latest_version=latest_version,
                            vulnerabilities=vulnerabilities,
                            risk_score=risk_score,
                            update_available=latest_version != current_version
                        )
                        
                        dependencies.append(dep_info)
        
        except Exception as e:
            print(f"Error scanning dependencies: {e}")
        
        return dependencies
    
    def scan_javascript_dependencies(self, package_json: str = "package.json") -> List[DependencyInfo]:
        """Scan JavaScript/Node dependencies for vulnerabilities"""
        dependencies = []
        
        try:
            with open(package_json, 'r') as f:
                data = json.load(f)
            
            all_deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
            
            for package_name, version_spec in all_deps.items():
                # Clean version spec
                current_version = version_spec.lstrip('^~>=<')
                
                # Check vulnerabilities
                vulnerabilities = self.check_osv_for_vulnerabilities(
                    package_name,
                    current_version
                )
                
                # Get latest version
                latest_version = self._get_latest_npm_version(package_name)
                
                risk_score = self._calculate_risk_score(vulnerabilities)
                
                dep_info = DependencyInfo(
                    name=package_name,
                    current_version=current_version,
                    latest_version=latest_version,
                    vulnerabilities=vulnerabilities,
                    risk_score=risk_score,
                    update_available=latest_version != current_version
                )
                
                dependencies.append(dep_info)
        
        except Exception as e:
            print(f"Error scanning JS dependencies: {e}")
        
        return dependencies
    
    def _get_severity_from_cvss(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level"""
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_risk_score(self, vulnerabilities: List[Vulnerability]) -> int:
        """Calculate overall risk score for a dependency"""
        if not vulnerabilities:
            return 0
        
        total_score = 0
        for vuln in vulnerabilities:
            # Weight by severity
            if vuln.severity == 'critical':
                total_score += 40
            elif vuln.severity == 'high':
                total_score += 25
            elif vuln.severity == 'medium':
                total_score += 10
            else:
                total_score += 5
            
            # Extra weight if exploit available
            if vuln.exploit_available:
                total_score += 20
        
        return min(total_score, 100)
    
    def _get_latest_version(self, package_name: str) -> str:
        """Get latest version from PyPI (simulated)"""
        try:
            response = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('info', {}).get('version', 'unknown')
        except:
            pass
        return 'unknown'
    
    def _get_latest_npm_version(self, package_name: str) -> str:
        """Get latest version from npm registry"""
        try:
            response = requests.get(f"https://registry.npmjs.org/{package_name}/latest", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('version', 'unknown')
        except:
            pass
        return 'unknown'
    
    def create_alert(self, vulnerability: Vulnerability, affected_deps: List[str]) -> CVEAlert:
        """Create a CVE alert based on severity"""
        # Get SLA deadline based on severity
        _, _, sla_delta = self.severity_thresholds[vulnerability.severity]
        sla_deadline = datetime.now() + sla_delta
        
        # Determine recommended action
        if vulnerability.severity == 'critical':
            recommended_action = "Immediate patching required. Apply updates within next release cycle."
        elif vulnerability.severity == 'high':
            recommended_action = "Patch within 24 hours. Test in staging first."
        elif vulnerability.severity == 'medium':
            recommended_action = "Schedule patch within next sprint."
        else:
            recommended_action = "Monitor for updates. Patch during next maintenance window."
        
        alert = CVEAlert(
            alert_id=f"CVE-ALERT-{datetime.now().timestamp()}",
            vulnerability=vulnerability,
            affected_dependencies=affected_deps,
            severity_level=vulnerability.severity,
            recommended_action=recommended_action,
            sla_deadline=sla_deadline
        )
        
        return alert
    
    def monitor_continuous(self, check_interval_hours: int = 24):
        """Continuous monitoring mode"""
        print(f"🔍 CVE Monitor started - checking every {check_interval_hours} hours")
        
        # In production, this would run as a background task
        # For now, just perform one check
        alerts = []
        
        # Check Python dependencies
        python_deps = self.scan_python_dependencies()
        for dep in python_deps:
            if dep.vulnerabilities:
                alert = self.create_alert(dep.vulnerabilities[0], [dep.name])
                alerts.append(alert)
                print(f"⚠️  {alert.severity_level.upper()}: {dep.name} - {dep.vulnerabilities[0].cve_id}")
        
        # Check monitored products
        for product in list(self.monitored_products)[:5]:  # Limit to avoid rate limits
            vulns = self.check_nvd_for_vulnerabilities(product)
            if vulns:
                critical_vulns = [v for v in vulns if v.severity == 'critical']
                if critical_vulns:
                    alert = self.create_alert(critical_vulns[0], [product])
                    alerts.append(alert)
                    print(f"🚨 CRITICAL: {product} - {critical_vulns[0].cve_id}")
        
        return alerts
