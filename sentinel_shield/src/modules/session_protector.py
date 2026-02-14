"""
Sentinel Shield - Session & Cookie Protection
Prevents session hijacking, cookie theft, and token stealing attacks
"""

import os
import hashlib
import secrets
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json

# Optional psutil import
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None


class SessionStatus(Enum):
    """Session status"""
    ACTIVE = "active"
    LOCKED = "locked"
    EXPIRED = "expired"
    HIJACKED = "hijacked"


@dataclass
class SecureSession:
    """Represents a protected session"""
    session_id: str
    user_id: str
    device_fingerprint: str
    ip_address: str
    user_agent: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    status: SessionStatus = SessionStatus.ACTIVE
    usb_key_id: Optional[str] = None
    geo_location: Optional[str] = None
    risk_score: int = 0


@dataclass
class SessionAnomaly:
    """Detected session anomaly"""
    anomaly_id: str
    session_id: str
    anomaly_type: str
    severity: str
    description: str
    detected_at: datetime
    indicators: List[str] = field(default_factory=list)


class BrowserProfileProtector:
    """Protects browser profiles from malware access"""
    
    # Paths to protect (browser credential stores)
    PROTECTED_PATHS = {
        'chrome_windows': [
            r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data',
            r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies',
            r'%LOCALAPPDATA%\Google\Chrome\User Data\Local State',
        ],
        'firefox_windows': [
            r'%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json',
            r'%APPDATA%\Mozilla\Firefox\Profiles\*\key4.db',
            r'%APPDATA%\Mozilla\Firefox\Profiles\*\cookies.sqlite',
        ],
        'edge_windows': [
            r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data',
            r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies',
        ],
    }
    
    # Blocked process patterns
    MALWARE_PATTERNS = [
        'mimikatz', 'lazagne', 'browserghost', 'cookiemonster',
        'token_stealer', 'credential_dumper', 'infostealer'
    ]
    
    def __init__(self):
        self.monitored_paths: Set[str] = set()
        self.blocked_processes: Set[int] = set()
        self.access_log: List[Dict] = []
        self._initialize_monitoring()
    
    def _initialize_monitoring(self):
        """Initialize file system monitoring"""
        # Expand environment variables and add to monitored paths
        for browser, paths in self.PROTECTED_PATHS.items():
            for path_template in paths:
                expanded_path = os.path.expandvars(path_template)
                self.monitored_paths.add(expanded_path)
    
    def check_process_access(self, process_name: str, target_file: str) -> bool:
        """Check if process should be allowed to access browser files"""
        
        # Allow legitimate browser processes
        allowed_processes = [
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'brave.exe',
            'opera.exe', 'vivaldi.exe'
        ]
        
        if process_name.lower() in allowed_processes:
            return True
        
        # Block known malware patterns
        for pattern in self.MALWARE_PATTERNS:
            if pattern in process_name.lower():
                self._log_blocked_access(process_name, target_file, "malware_pattern")
                return False
        
        # Block unknown processes accessing browser credentials
        if any(protected in target_file for protected in ['Login Data', 'Cookies', 'key4.db', 'logins.json']):
            self._log_blocked_access(process_name, target_file, "suspicious_access")
            return False
        
        return True
    
    def monitor_active_processes(self) -> List[Dict]:
        """Monitor for suspicious processes accessing browser data"""
        suspicious = []
        
        if not PSUTIL_AVAILABLE:
            return suspicious
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):

                try:
                    proc_info = proc.info
                    process_name = proc_info['name']
                    
                    # Check if process has browser files open
                    if proc_info['open_files']:
                        for file in proc_info['open_files']:
                            file_path = file.path
                            
                            # Check against protected paths
                            for protected_path in self.monitored_paths:
                                if protected_path.lower() in file_path.lower():
                                    # Check if access should be allowed
                                    if not self.check_process_access(process_name, file_path):
                                        suspicious.append({
                                            'pid': proc_info['pid'],
                                            'name': process_name,
                                            'file': file_path,
                                            'action': 'blocked'
                                        })
                                        
                                        # Try to terminate malicious process
                                        self._terminate_process(proc_info['pid'])
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        
        except Exception as e:
            print(f"Error monitoring processes: {e}")
        
        return suspicious
    
    def _log_blocked_access(self, process_name: str, target_file: str, reason: str):
        """Log blocked file access"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'process': process_name,
            'target': target_file,
            'reason': reason,
            'action': 'blocked'
        }
        self.access_log.append(log_entry)
        print(f"🚫 BLOCKED: {process_name} attempting to access {target_file}")
    
    def _terminate_process(self, pid: int):
        """Terminate malicious process"""
        if not PSUTIL_AVAILABLE:
            return
        try:
            process = psutil.Process(pid)

            process.terminate()
            self.blocked_processes.add(pid)
            print(f"🛑 TERMINATED: Process {pid}")
        except Exception as e:
            print(f"Failed to terminate process {pid}: {e}")


class SessionManager:
    """Manages secure sessions with USB key integration"""
    
    def __init__(self):
        self.active_sessions: Dict[str, SecureSession] = {}
        self.anomalies: List[SessionAnomaly] = []
        self.browser_protector = BrowserProfileProtector()
        
        # Session security settings
        self.session_timeout_minutes = 30
        self.max_inactive_minutes = 15
        self.require_usb_key = False  # Enable when USB keys are deployed
    
    def create_session(self, user_id: str, ip_address: str, 
                       user_agent: str, usb_key_id: Optional[str] = None) -> SecureSession:
        """Create a new secure session"""
        
        # Generate secure session ID
        session_id = secrets.token_urlsafe(32)
        
        # Create device fingerprint
        device_fingerprint = self._create_device_fingerprint(ip_address, user_agent)
        
        # Calculate expiry
        created_at = datetime.now()
        expires_at = created_at + timedelta(minutes=self.session_timeout_minutes)
        
        session = SecureSession(
            session_id=session_id,
            user_id=user_id,
            device_fingerprint=device_fingerprint,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=created_at,
            last_activity=created_at,
            expires_at=expires_at,
            usb_key_id=usb_key_id
        )
        
        self.active_sessions[session_id] = session
        return session
    
    def validate_session(self, session_id: str, ip_address: str, 
                         user_agent: str, usb_key_id: Optional[str] = None) -> bool:
        """Validate session and check for anomalies"""
        
        session = self.active_sessions.get(session_id)
        if not session:
            return False
        
        # Check if session is expired
        if datetime.now() > session.expires_at:
            session.status = SessionStatus.EXPIRED
            return False
        
        # Check if session is locked or hijacked
        if session.status in [SessionStatus.LOCKED, SessionStatus.HIJACKED]:
            return False
        
        # Check for session hijacking indicators
        anomalies = self._detect_anomalies(session, ip_address, user_agent, usb_key_id)
        
        if anomalies:
            # Critical anomalies = session hijacking
            critical_anomalies = [a for a in anomalies if a.severity == 'critical']
            if critical_anomalies:
                session.status = SessionStatus.HIJACKED
                self.anomalies.extend(anomalies)
                return False
            
            # High severity = lock session
            high_anomalies = [a for a in anomalies if a.severity == 'high']
            if high_anomalies:
                session.status = SessionStatus.LOCKED
                self.anomalies.extend(anomalies)
                return False
        
        # Update last activity
        session.last_activity = datetime.now()
        
        return True
    
    def _detect_anomalies(self, session: SecureSession, ip_address: str,
                          user_agent: str, usb_key_id: Optional[str]) -> List[SessionAnomaly]:
        """Detect session anomalies"""
        anomalies = []
        
        # 1. IP address change
        if ip_address != session.ip_address:
            anomalies.append(SessionAnomaly(
                anomaly_id=f"ANOM-{datetime.now().timestamp()}",
                session_id=session.session_id,
                anomaly_type="ip_change",
                severity="high",
                description=f"IP changed from {session.ip_address} to {ip_address}",
                detected_at=datetime.now(),
                indicators=["ip_mismatch"]
            ))
        
        # 2. User agent change
        if user_agent != session.user_agent:
            anomalies.append(SessionAnomaly(
                anomaly_id=f"ANOM-{datetime.now().timestamp()}",
                session_id=session.session_id,
                anomaly_type="user_agent_change",
                severity="high",
                description="User agent changed during session",
                detected_at=datetime.now(),
                indicators=["user_agent_mismatch"]
            ))
        
        # 3. USB key mismatch (if using USB keys)
        if self.require_usb_key:
            if usb_key_id != session.usb_key_id:
                anomalies.append(SessionAnomaly(
                    anomaly_id=f"ANOM-{datetime.now().timestamp()}",
                    session_id=session.session_id,
                    anomaly_type="usb_key_mismatch",
                    severity="critical",
                    description="USB security key does not match session",
                    detected_at=datetime.now(),
                    indicators=["usb_key_missing", "possible_hijacking"]
                ))
        
        # 4. Impossible travel
        if hasattr(session, 'geo_location') and session.geo_location:
            # In production, check if IP geolocation changed impossibly fast
            pass
        
        # 5. Session inactivity
        time_since_activity = datetime.now() - session.last_activity
        if time_since_activity.total_seconds() > (self.max_inactive_minutes * 60):
            anomalies.append(SessionAnomaly(
                anomaly_id=f"ANOM-{datetime.now().timestamp()}",
                session_id=session.session_id,
                anomaly_type="inactivity_timeout",
                severity="medium",
                description=f"Session inactive for {time_since_activity.total_seconds()/60:.1f} minutes",
                detected_at=datetime.now(),
                indicators=["timeout"]
            ))
        
        return anomalies
    
    def _create_device_fingerprint(self, ip_address: str, user_agent: str) -> str:
        """Create device fingerprint"""
        fingerprint_data = f"{ip_address}:{user_agent}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    def revoke_session(self, session_id: str):
        """Revoke a session"""
        if session_id in self.active_sessions:
            self.active_sessions[session_id].status = SessionStatus.EXPIRED
            del self.active_sessions[session_id]
    
    def revoke_all_user_sessions(self, user_id: str):
        """Revoke all sessions for a user"""
        sessions_to_revoke = [
            sid for sid, session in self.active_sessions.items()
            if session.user_id == user_id
        ]
        
        for sid in sessions_to_revoke:
            self.revoke_session(sid)
    
    def get_session_report(self) -> Dict:
        """Generate session security report"""
        return {
            "active_sessions": len(self.active_sessions),
            "anomalies_detected": len(self.anomalies),
            "hijacking_attempts": len([a for a in self.anomalies if a.anomaly_type == "usb_key_mismatch"]),
            "ip_changes": len([a for a in self.anomalies if a.anomaly_type == "ip_change"]),
            "browser_protection_blocks": len(self.browser_protector.access_log),
            "terminated_processes": len(self.browser_protector.blocked_processes),
        }


class USBKeyManager:
    """Manages USB security keys (hardware tokens)"""
    
    def __init__(self):
        self.registered_keys: Dict[str, Dict] = {}
        self.key_sessions: Dict[str, str] = {}  # key_id -> session_id
    
    def register_key(self, key_id: str, user_id: str) -> bool:
        """Register a new USB key"""
        self.registered_keys[key_id] = {
            'user_id': user_id,
            'registered_at': datetime.now().isoformat(),
            'last_used': None
        }
        return True
    
    def verify_key(self, key_id: str) -> Optional[str]:
        """Verify USB key and return user_id"""
        key_data = self.registered_keys.get(key_id)
        if key_data:
            key_data['last_used'] = datetime.now().isoformat()
            return key_data['user_id']
        return None
    
    def bind_key_to_session(self, key_id: str, session_id: str):
        """Bind USB key to session"""
        self.key_sessions[key_id] = session_id
    
    def get_session_for_key(self, key_id: str) -> Optional[str]:
        """Get session ID for USB key"""
        return self.key_sessions.get(key_id)
