"""
Sentinel Shield - Privilege Escalation Monitor
Real-time detection and prevention of privilege escalation attempts
"""

import os
import subprocess
import psutil
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import re


class EscalationType(Enum):
    """Types of privilege escalation"""
    SUDO_ABUSE = "sudo_abuse"
    SUID_EXPLOITATION = "suid_exploitation"
    KERNEL_EXPLOIT = "kernel_exploit"
    DLL_HIJACKING = "dll_hijacking"
    SERVICE_MISCONFIGURATION = "service_misconfiguration"
    TOKEN_MANIPULATION = "token_manipulation"
    UAC_BYPASS = "uac_bypass"
    SCHEDULED_TASK_ABUSE = "scheduled_task_abuse"
    REGISTRY_MANIPULATION = "registry_manipulation"


@dataclass
class PrivilegeEscalationEvent:
    """Detected privilege escalation attempt"""
    event_id: str
    escalation_type: EscalationType
    user: str
    process_name: str
    process_id: int
    parent_process: str
    command_line: str
    severity: str  # critical, high, medium, low
    timestamp: datetime = field(default_factory=datetime.now)
    blocked: bool = False
    details: Dict = field(default_factory=dict)


@dataclass
class UserActivity:
    """Track user privilege usage"""
    username: str
    admin_commands: List[str] = field(default_factory=list)
    failed_attempts: int = 0
    successful_escalations: int = 0
    last_admin_action: Optional[datetime] = None
    is_suspicious: bool = False


class SuspiciousCommandDetector:
    """Detects suspicious commands indicating privilege escalation"""
    
    # Suspicious Windows commands
    WINDOWS_SUSPICIOUS = [
        r'net\s+(user|localgroup).*(add|/add)',  # User/group manipulation
        r'reg\s+add.*HKLM',  # Registry modification
        r'schtasks\s+/create',  # Scheduled task creation
        r'sc\s+(create|config)',  # Service creation/modification
        r'powershell.*-exec\s+bypass',  # Execution policy bypass
        r'wmic\s+process\s+call\s+create',  # Remote process creation
        r'psexec',  # Remote execution
        r'mimikatz',  # Credential dumping
        r'procdump',  # Process dumping
        r'ntdsutil',  # AD database access
        r'vssadmin.*delete\s+shadows',  # Shadow copy deletion (ransomware)
    ]
    
    # Suspicious Linux commands
    LINUX_SUSPICIOUS = [
        r'sudo\s+-i',  # Root shell
        r'sudo\s+su',  # Switch to root
        r'chmod\s+[+]?s',  # SUID bit setting
        r'chown\s+root',  # Change ownership to root
        r'/etc/passwd',  # Password file access
        r'/etc/shadow',  # Shadow file access
        r'LD_PRELOAD',  # Library preloading
        r'docker\s+run.*--privileged',  # Privileged container
        r'kubectl\s+exec',  # Kubernetes exec
        r'modprobe',  # Kernel module loading
    ]
    
    @classmethod
    def is_suspicious(cls, command: str) -> tuple[bool, Optional[str]]:
        """Check if command is suspicious"""
        
        # Check Windows patterns
        for pattern in cls.WINDOWS_SUSPICIOUS:
            if re.search(pattern, command, re.IGNORECASE):
                return True, f"Suspicious Windows command: {pattern}"
        
        # Check Linux patterns
        for pattern in cls.LINUX_SUSPICIOUS:
            if re.search(pattern, command, re.IGNORECASE):
                return True, f"Suspicious Linux command: {pattern}"
        
        return False, None


class ProcessMonitor:
    """Monitor processes for privilege escalation"""
    
    @staticmethod
    def detect_token_manipulation() -> List[PrivilegeEscalationEvent]:
        """Detect token manipulation attempts"""
        events = []
        
        try:
            # Check for processes running with unexpected privileges
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    proc_info = proc.info
                    
                    # Check if non-admin user has admin process
                    if proc_info['username'] and 'SYSTEM' not in proc_info['username']:
                        # In production: Check process token privileges
                        pass
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            print(f"Token detection error: {e}")
        
        return events
    
    @staticmethod
    def detect_dll_hijacking() -> List[PrivilegeEscalationEvent]:
        """Detect DLL hijacking attempts"""
        events = []
        
        # Check for DLLs in suspicious locations
        suspicious_paths = [
            "C:\\Windows\\Temp",
            "C:\\Users\\Public",
            os.path.expanduser("~\\AppData\\Local\\Temp")
        ]
        
        for path in suspicious_paths:
            if os.path.exists(path):
                try:
                    for file in os.listdir(path):
                        if file.endswith('.dll'):
                            # DLL in temp folder is suspicious
                            event = PrivilegeEscalationEvent(
                                event_id=f"PE-DLL-{datetime.now().timestamp()}",
                                escalation_type=EscalationType.DLL_HIJACKING,
                                user="unknown",
                                process_name="explorer.exe",
                                process_id=0,
                                parent_process="unknown",
                                command_line=f"Suspicious DLL: {os.path.join(path, file)}",
                                severity="medium"
                            )
                            events.append(event)
                except (PermissionError, FileNotFoundError):
                    pass
        
        return events
    
    @staticmethod
    def detect_uac_bypass() -> List[PrivilegeEscalationEvent]:
        """Detect UAC bypass attempts"""
        events = []
        
        # Common UAC bypass techniques
        bypass_indicators = [
            "eventvwr.exe",  # Event Viewer UAC bypass
            "fodhelper.exe",  # FOD Helper bypass
            "computerdefaults.exe",  # Computer Defaults bypass
            "sdclt.exe",  # Backup and Restore bypass
        ]
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                if proc.info['name'] in bypass_indicators:
                    event = PrivilegeEscalationEvent(
                        event_id=f"PE-UAC-{proc.info['pid']}",
                        escalation_type=EscalationType.UAC_BYPASS,
                        user=proc.info.get('username', 'unknown'),
                        process_name=proc.info['name'],
                        process_id=proc.info['pid'],
                        parent_process="unknown",
                        command_line=' '.join(proc.info.get('cmdline', [])),
                        severity="high",
                        details={"technique": "UAC bypass via " + proc.info['name']}
                    )
                    events.append(event)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return events


class RegistryMonitor:
    """Monitor Windows Registry for suspicious changes"""
    
    CRITICAL_KEYS = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SYSTEM\CurrentControlSet\Services",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ]
    
    @staticmethod
    def detect_persistence() -> List[PrivilegeEscalationEvent]:
        """Detect registry-based persistence mechanisms"""
        events = []
        
        # In production: Monitor registry changes in real-time
        # For now, simulate detection
        
        return events


class ServiceMonitor:
    """Monitor Windows services for misconfigurations"""
    
    @staticmethod
    def detect_service_abuse() -> List[PrivilegeEscalationEvent]:
        """Detect service-based privilege escalation"""
        events = []
        
        try:
            # Get all services
            if os.name == 'nt':
                result = subprocess.run(
                    ['sc', 'query', 'state=', 'all'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                # Check for suspicious service names
                suspicious_names = ['malware', 'hack', 'admin', 'system32']
                
                for line in result.stdout.split('\n'):
                    if 'SERVICE_NAME:' in line:
                        service_name = line.split(':')[1].strip().lower()
                        if any(sus in service_name for sus in suspicious_names):
                            event = PrivilegeEscalationEvent(
                                event_id=f"PE-SVC-{service_name}",
                                escalation_type=EscalationType.SERVICE_MISCONFIGURATION,
                                user="SYSTEM",
                                process_name="services.exe",
                                process_id=0,
                                parent_process="system",
                                command_line=f"Suspicious service: {service_name}",
                                severity="high"
                            )
                            events.append(event)
        except Exception as e:
            print(f"Service monitor error: {e}")
        
        return events


class PrivilegeEscalationMonitor:
    """Main privilege escalation monitoring system"""
    
    def __init__(self):
        self.user_activities: Dict[str, UserActivity] = {}
        self.detected_events: List[PrivilegeEscalationEvent] = []
        self.blocked_users: Set[str] = set()
        self.command_detector = SuspiciousCommandDetector()
        self.process_monitor = ProcessMonitor()
        self.registry_monitor = RegistryMonitor()
        self.service_monitor = ServiceMonitor()
    
    def monitor_command(self, user: str, command: str, process_id: int) -> Optional[PrivilegeEscalationEvent]:
        """Monitor a command execution"""
        
        # Check if user is blocked
        if user in self.blocked_users:
            print(f"🚫 BLOCKED: User {user} is blocked from executing commands")
            return None
        
        # Check if command is suspicious
        is_suspicious, reason = self.command_detector.is_suspicious(command)
        
        if is_suspicious:
            # Track user activity
            if user not in self.user_activities:
                self.user_activities[user] = UserActivity(username=user)
            
            activity = self.user_activities[user]
            activity.admin_commands.append(command)
            activity.last_admin_action = datetime.now()
            
            # Create event
            event = PrivilegeEscalationEvent(
                event_id=f"PE-CMD-{process_id}",
                escalation_type=EscalationType.SUDO_ABUSE,
                user=user,
                process_name="cmd.exe",
                process_id=process_id,
                parent_process="explorer.exe",
                command_line=command,
                severity="high",
                details={"reason": reason}
            )
            
            self.detected_events.append(event)
            
            # Check if should block user
            if activity.failed_attempts > 3:
                self._block_user(user, "Multiple privilege escalation attempts")
                event.blocked = True
            
            print(f"⚠️ SUSPICIOUS COMMAND: {user} executed: {command}")
            print(f"   Reason: {reason}")
            
            return event
        
        return None
    
    def scan_system(self) -> List[PrivilegeEscalationEvent]:
        """Perform full system scan for privilege escalation indicators"""
        
        print("\n🔍 Starting privilege escalation scan...")
        
        all_events = []
        
        # Scan processes
        print("   Checking for token manipulation...")
        all_events.extend(self.process_monitor.detect_token_manipulation())
        
        print("   Checking for DLL hijacking...")
        all_events.extend(self.process_monitor.detect_dll_hijacking())
        
        print("   Checking for UAC bypass...")
        all_events.extend(self.process_monitor.detect_uac_bypass())
        
        # Scan services
        print("   Checking services...")
        all_events.extend(self.service_monitor.detect_service_abuse())
        
        # Scan registry
        print("   Checking registry...")
        all_events.extend(self.registry_monitor.detect_persistence())
        
        self.detected_events.extend(all_events)
        
        print(f"✅ Scan complete: {len(all_events)} threats detected\n")
        
        return all_events
    
    def _block_user(self, username: str, reason: str):
        """Block user from further privilege escalation"""
        self.blocked_users.add(username)
        print(f"🔒 BLOCKED USER: {username}")
        print(f"   Reason: {reason}")
        
        # In production: Revoke privileges via Active Directory or local security policy
    
    def get_user_risk_score(self, username: str) -> int:
        """Calculate user risk score based on activity"""
        if username not in self.user_activities:
            return 0
        
        activity = self.user_activities[username]
        score = 0
        
        # Failed attempts
        score += activity.failed_attempts * 15
        
        # Suspicious commands
        score += len(activity.admin_commands) * 10
        
        # Recent activity (last 10 minutes)
        if activity.last_admin_action:
            time_diff = datetime.now() - activity.last_admin_action
            if time_diff < timedelta(minutes=10):
                score += 20
        
        # Marked as suspicious
        if activity.is_suspicious:
            score += 30
        
        return min(score, 100)
    
    def get_summary(self) -> Dict:
        """Get monitoring summary"""
        return {
            "total_events": len(self.detected_events),
            "blocked_users": list(self.blocked_users),
            "monitored_users": len(self.user_activities),
            "high_risk_users": [
                user for user, activity in self.user_activities.items()
                if self.get_user_risk_score(user) >= 70
            ],
            "event_types": {
                etype.value: sum(1 for e in self.detected_events if e.escalation_type == etype)
                for etype in EscalationType
            }
        }
