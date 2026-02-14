"""
Sentinel Shield - Integration Tests for New Security Modules
Tests for CVE Monitor, DLP Engine, and Session Protection
"""

import pytest
import sys
import os
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'modules'))

from cve_monitor import CVEMonitor, Vulnerability, Severity
from dlp_engine import DLPEngine, Violation, Action
from session_protector import SessionManager, USBKeyManager, BrowserProfileProtector


class TestCVEMonitor:
    """Tests for CVE Vulnerability Monitor"""
    
    def test_cve_monitor_initialization(self):
        """Test CVE monitor initializes correctly"""
        monitor = CVEMonitor()
        assert monitor is not None
        assert len(monitor.vulnerability_cache) == 0
        assert len(monitor.monitored_products) == 0
    
    def test_vulnerability_classification(self):
        """Test CVSS score-based severity classification"""
        monitor = CVEMonitor()
        
        # Critical vulnerability (CVSS 9.0+)
        critical_vuln = Vulnerability(
            cve_id="CVE-2024-1234",
            description="Remote Code Execution",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            affected_product="example-product",
            affected_versions=["1.0.0"],
            published_date=datetime.now()
        )
        
        assert critical_vuln.severity == Severity.CRITICAL
        assert critical_vuln.cvss_score >= 9.0
        
        # High vulnerability (CVSS 7.0-8.9)
        high_vuln = Vulnerability(
            cve_id="CVE-2024-5678",
            description="SQL Injection",
            severity=Severity.HIGH,
            cvss_score=8.5,
            affected_product="example-product",
            affected_versions=["2.0.0"],
            published_date=datetime.now()
        )
        
        assert high_vuln.severity == Severity.HIGH
        assert 7.0 <= high_vuln.cvss_score < 9.0
    
    def test_add_monitored_product(self):
        """Test adding products to monitoring list"""
        monitor = CVEMonitor()
        
        monitor.add_monitored_product("spring-boot", "2.7.0")
        monitor.add_monitored_product("django", "4.2.0")
        
        assert len(monitor.monitored_products) == 2
        assert ("spring-boot", "2.7.0") in monitor.monitored_products
        assert ("django", "4.2.0") in monitor.monitored_products
    
    def test_parse_requirements_txt(self):
        """Test parsing Python requirements.txt for dependencies"""
        monitor = CVEMonitor()
        
        # Create sample requirements.txt content
        requirements_content = """
fastapi==0.104.1
uvicorn==0.24.0
pydantic==2.5.0
# Comment line
pytest>=7.4.0
        """
        
        dependencies = monitor._parse_requirements_txt(requirements_content)
        
        assert len(dependencies) >= 3
        assert any(d['name'] == 'fastapi' for d in dependencies)
        assert any(d['name'] == 'uvicorn' for d in dependencies)
        assert any(d['name'] == 'pydantic' for d in dependencies)
    
    def test_parse_package_json(self):
        """Test parsing package.json for JavaScript dependencies"""
        monitor = CVEMonitor()
        
        # Create sample package.json content
        package_json_content = """
{
    "dependencies": {
        "react": "^18.2.0",
        "express": "^4.18.2",
        "axios": "^1.6.0"
    },
    "devDependencies": {
        "vite": "^5.0.0"
    }
}
        """
        
        dependencies = monitor._parse_package_json(package_json_content)
        
        assert len(dependencies) >= 3
        assert any(d['name'] == 'react' for d in dependencies)
        assert any(d['name'] == 'express' for d in dependencies)


class TestDLPEngine:
    """Tests for Data Loss Prevention Engine"""
    
    def test_dlp_engine_initialization(self):
        """Test DLP engine initializes with default policies"""
        dlp = DLPEngine()
        
        assert dlp is not None
        assert len(dlp.policies) >= 4  # Financial, PII, Secrets, Internal
        assert len(dlp.pattern_library.patterns) > 0
    
    def test_credit_card_detection(self):
        """Test credit card pattern detection"""
        dlp = DLPEngine()
        
        # Test Visa card
        text_visa = "My Visa card is 4532-1488-0343-6467"
        matches_visa = dlp.pattern_library.find_matches(text_visa)
        
        assert len(matches_visa) > 0
        assert any('credit_card' in m.pattern_id for m in matches_visa)
        
        # Test Mastercard
        text_mc = "Mastercard: 5425-2334-3010-9903"
        matches_mc = dlp.pattern_library.find_matches(text_mc)
        
        assert len(matches_mc) > 0
        
        # Test American Express
        text_amex = "Amex 3782-822463-10005"
        matches_amex = dlp.pattern_library.find_matches(text_amex)
        
        assert len(matches_amex) > 0
    
    def test_ssn_detection(self):
        """Test Social Security Number detection"""
        dlp = DLPEngine()
        
        text = "My SSN is 123-45-6789"
        matches = dlp.pattern_library.find_matches(text)
        
        assert len(matches) > 0
        assert any('ssn' in m.pattern_id for m in matches)
    
    def test_api_key_detection(self):
        """Test API key detection"""
        dlp = DLPEngine()
        
        text_aws = "AWS Key: AKIAIOSFODNN7EXAMPLE"
        matches_aws = dlp.pattern_library.find_matches(text_aws)
        
        assert len(matches_aws) > 0
        assert any('api_key' in m.pattern_id for m in matches_aws)
    
    def test_email_content_scan(self):
        """Test scanning email content for sensitive data"""
        dlp = DLPEngine()
        
        email_content = """
        Dear Customer,
        
        Your credit card 4532-1488-0343-6467 has been charged.
        For questions, contact us at support@example.com.
        
        SSN: 123-45-6789
        """
        
        violations = dlp.check_email_content(
            sender="attacker@evil.com",
            recipient="victim@company.com",
            subject="Payment Confirmation",
            body=email_content
        )
        
        assert len(violations) > 0
        assert any(v.violation_type == 'credit_card' for v in violations)
        assert any(v.violation_type == 'ssn' for v in violations)
    
    def test_luhn_algorithm_validation(self):
        """Test Luhn algorithm for credit card validation"""
        dlp = DLPEngine()
        
        # Valid Visa card (passes Luhn check)
        assert dlp.pattern_library._luhn_check("4532148803436467") == True
        
        # Invalid card number
        assert dlp.pattern_library._luhn_check("4532148803436468") == False
    
    def test_policy_matching(self):
        """Test DLP policy matching"""
        dlp = DLPEngine()
        
        # Financial data should trigger Financial policy
        financial_text = "Card: 4532-1488-0343-6467"
        violations_financial = dlp.check_email_content("user@company.com", "external@other.com", "Payment", financial_text)
        
        assert any(v.policy_name == "Financial Data Protection" for v in violations_financial)
        
        # PII data should trigger PII policy
        pii_text = "SSN: 123-45-6789"
        violations_pii = dlp.check_email_content("user@company.com", "external@other.com", "Personal Info", pii_text)
        
        assert any(v.policy_name == "Personally Identifiable Information" for v in violations_pii)
    
    def test_content_redaction(self):
        """Test automatic content redaction"""
        dlp = DLPEngine()
        
        original_text = "My credit card is 4532-1488-0343-6467 and SSN is 123-45-6789"
        redacted_text = dlp.redact_sensitive_content(original_text)
        
        # Should not contain original sensitive data
        assert "4532-1488-0343-6467" not in redacted_text
        assert "123-45-6789" not in redacted_text
        
        # Should contain redaction markers
        assert "[REDACTED" in redacted_text


class TestSessionProtection:
    """Tests for Session & Cookie Protection"""
    
    def test_session_manager_initialization(self):
        """Test session manager initializes correctly"""
        manager = SessionManager()
        
        assert manager is not None
        assert len(manager.active_sessions) == 0
        assert len(manager.anomalies) == 0
    
    def test_create_session(self):
        """Test creating a new secure session"""
        manager = SessionManager()
        
        session = manager.create_session(
            user_id="user123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        )
        
        assert session is not None
        assert session.user_id == "user123"
        assert session.ip_address == "192.168.1.100"
        assert session.session_id in manager.active_sessions
        assert session.device_fingerprint is not None
    
    def test_session_validation(self):
        """Test session validation with same IP and user-agent"""
        manager = SessionManager()
        
        # Create session
        session = manager.create_session(
            user_id="user123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0"
        )
        
        # Validate with same credentials
        is_valid = manager.validate_session(
            session_id=session.session_id,
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0"
        )
        
        assert is_valid == True
    
    def test_ip_change_detection(self):
        """Test detection of IP address changes"""
        manager = SessionManager()
        
        # Create session
        session = manager.create_session(
            user_id="user123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0"
        )
        
        # Validate with different IP
        is_valid = manager.validate_session(
            session_id=session.session_id,
            ip_address="10.0.0.50",  # Different IP
            user_agent="Mozilla/5.0"
        )
        
        # Should detect anomaly
        assert len(manager.anomalies) > 0
        assert any(a.anomaly_type == "ip_change" for a in manager.anomalies)
    
    def test_user_agent_change_detection(self):
        """Test detection of user-agent changes"""
        manager = SessionManager()
        
        # Create session
        session = manager.create_session(
            user_id="user123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 (Windows)"
        )
        
        # Validate with different user-agent
        is_valid = manager.validate_session(
            session_id=session.session_id,
            ip_address="192.168.1.100",
            user_agent="Chrome/120.0"  # Different browser
        )
        
        # Should detect anomaly
        assert any(a.anomaly_type == "user_agent_change" for a in manager.anomalies)
    
    def test_session_revocation(self):
        """Test session revocation"""
        manager = SessionManager()
        
        session = manager.create_session(
            user_id="user123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0"
        )
        
        # Revoke session
        manager.revoke_session(session.session_id)
        
        # Session should be revoked
        assert manager.active_sessions[session.session_id].status.value == "revoked"
    
    def test_usb_key_manager(self):
        """Test USB key registration and verification"""
        usb_manager = USBKeyManager()
        
        # Register key
        success = usb_manager.register_key("USB-KEY-12345", "user123")
        assert success == True
        
        # Verify key
        user_id = usb_manager.verify_key("USB-KEY-12345")
        assert user_id == "user123"
        
        # Invalid key
        invalid_user = usb_manager.verify_key("INVALID-KEY")
        assert invalid_user is None
    
    def test_usb_key_session_binding(self):
        """Test binding USB keys to sessions"""
        usb_manager = USBKeyManager()
        
        # Register key
        usb_manager.register_key("USB-KEY-12345", "user123")
        
        # Bind to session
        usb_manager.bind_key_to_session("USB-KEY-12345", "session-abc-123")
        
        # Get session for key
        session_id = usb_manager.get_session_for_key("USB-KEY-12345")
        assert session_id == "session-abc-123"
    
    def test_browser_protector_initialization(self):
        """Test browser profile protector initialization"""
        protector = BrowserProfileProtector()
        
        assert protector is not None
        assert len(protector.monitored_paths) > 0
        assert len(protector.access_log) == 0


class TestIntegrationScenarios:
    """Integration tests combining multiple modules"""
    
    def test_full_security_pipeline(self):
        """Test complete security pipeline: CVE + DLP + Session"""
        
        # Initialize all modules
        cve_monitor = CVEMonitor()
        dlp_engine = DLPEngine()
        session_manager = SessionManager()
        
        # Scenario: User logs in and attempts to exfiltrate data
        
        # 1. Create secure session
        session = session_manager.create_session(
            user_id="employee@company.com",
            ip_address="192.168.1.50",
            user_agent="Mozilla/5.0"
        )
        
        assert session is not None
        
        # 2. Check for vulnerabilities in dependencies
        cve_monitor.add_monitored_product("fastapi", "0.100.0")
        
        # 3. User attempts to send sensitive email
        email_body = """
        Forwarding customer data:
        Credit Card: 4532-1488-0343-6467
        SSN: 123-45-6789
        """
        
        violations = dlp_engine.check_email_content(
            sender="employee@company.com",
            recipient="attacker@external.com",
            subject="Customer Data",
            body=email_body
        )
        
        # DLP should detect violations
        assert len(violations) >= 2
        assert violations[0].action == Action.BLOCK
        
        # 4. Suspicious IP change detected
        session_manager.validate_session(
            session_id=session.session_id,
            ip_address="203.0.113.50",  # Suspicious external IP
            user_agent="Mozilla/5.0"
        )
        
        # Should detect IP anomaly
        anomalies = [a for a in session_manager.anomalies if a.session_id == session.session_id]
        assert len(anomalies) > 0
        
        # Full security coverage achieved
        assert len(violations) > 0  # DLP caught data exfiltration
        assert len(anomalies) > 0  # Session protection caught suspicious behavior


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])
