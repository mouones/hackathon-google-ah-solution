"""
Sentinel Shield - Automated Threat Response System
Sub-second threat containment with machine isolation and automated workflows
"""

import asyncio
import subprocess
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import socket
import psutil


class ThreatLevel(Enum):
    """Threat severity levels"""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    CRITICAL = "critical"


class ResponseAction(Enum):
    """Available response actions"""
    QUARANTINE_EMAIL = "quarantine_email"
    BLOCK_SENDER = "block_sender"
    ISOLATE_MACHINE = "isolate_machine"
    KILL_PROCESS = "kill_process"
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    REVOKE_PRIVILEGES = "revoke_privileges"
    LOCK_ACCOUNT = "lock_account"
    ALERT_ADMIN = "alert_admin"
    BACKUP_DATA = "backup_data"
    CAPTURE_FORENSICS = "capture_forensics"


@dataclass
class ThreatEvent:
    """Represents a detected threat"""
    event_id: str
    threat_type: str  # phishing, malware, privilege_escalation, etc.
    threat_level: ThreatLevel
    threat_score: int
    source_ip: Optional[str] = None
    source_machine: Optional[str] = None
    source_user: Optional[str] = None
    affected_systems: List[str] = field(default_factory=list)
    details: Dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ResponseWorkflow:
    """Automated response workflow"""
    workflow_id: str
    threat_event: ThreatEvent
    actions: List[ResponseAction]
    execution_order: List[int]  # Order of action execution
    max_execution_time: int = 1000  # milliseconds
    

@dataclass
class ActionResult:
    """Result of a response action"""
    action: ResponseAction
    success: bool
    execution_time_ms: int
    message: str
    details: Dict = field(default_factory=dict)


class MachineIsolationEngine:
    """Isolates compromised machines from network"""
    
    @staticmethod
    async def isolate(machine_id: str, reason: str) -> ActionResult:
        """Isolate machine from network"""
        start_time = datetime.now()
        
        try:
            # In production, this would:
            # 1. Move machine to quarantine VLAN
            # 2. Block all outbound traffic except to security servers
            # 3. Disable network adapters via Group Policy
            # 4. Force VPN disconnection
            
            # Simulated isolation
            isolation_commands = [
                f"# Move {machine_id} to quarantine VLAN",
                f"# Block outbound traffic for {machine_id}",
                f"# Disable network adapters on {machine_id}",
                f"# Alert admin about {machine_id} isolation"
            ]
            
            # Log isolation
            print(f"🔒 ISOLATED: Machine {machine_id} - Reason: {reason}")
            
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return ActionResult(
                action=ResponseAction.ISOLATE_MACHINE,
                success=True,
                execution_time_ms=execution_time,
                message=f"Machine {machine_id} successfully isolated",
                details={
                    "machine_id": machine_id,
                    "reason": reason,
                    "commands_executed": isolation_commands
                }
            )
        except Exception as e:
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            return ActionResult(
                action=ResponseAction.ISOLATE_MACHINE,
                success=False,
                execution_time_ms=execution_time,
                message=f"Failed to isolate machine: {str(e)}"
            )
    
    @staticmethod
    async def restore(machine_id: str) -> bool:
        """Restore machine to normal network"""
        try:
            print(f"✅ RESTORED: Machine {machine_id} returned to normal network")
            return True
        except Exception:
            return False


class FirewallController:
    """Controls firewall rules for threat blocking"""
    
    @staticmethod
    async def block_ip(ip_address: str, duration_minutes: Optional[int] = None) -> ActionResult:
        """Block IP address at firewall"""
        start_time = datetime.now()
        
        try:
            # In production, this would interface with:
            # - Windows Firewall (netsh)
            # - pfSense API
            # - iptables
            # - Azure Firewall
            
            command = f"netsh advfirewall firewall add rule name=\"Sentinel_Block_{ip_address}\" dir=in action=block remoteip={ip_address}"
            
            print(f"🚫 BLOCKED IP: {ip_address}")
            
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return ActionResult(
                action=ResponseAction.BLOCK_IP,
                success=True,
                execution_time_ms=execution_time,
                message=f"IP {ip_address} blocked",
                details={"ip": ip_address, "duration_minutes": duration_minutes}
            )
        except Exception as e:
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            return ActionResult(
                action=ResponseAction.BLOCK_IP,
                success=False,
                execution_time_ms=execution_time,
                message=f"Failed to block IP: {str(e)}"
            )
    
    @staticmethod
    async def block_domain(domain: str) -> ActionResult:
        """Block domain via DNS/firewall"""
        start_time = datetime.now()
        
        try:
            # Add to DNS blocklist or firewall domain filter
            print(f"🚫 BLOCKED DOMAIN: {domain}")
            
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return ActionResult(
                action=ResponseAction.BLOCK_DOMAIN,
                success=True,
                execution_time_ms=execution_time,
                message=f"Domain {domain} blocked",
                details={"domain": domain}
            )
        except Exception as e:
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            return ActionResult(
                action=ResponseAction.BLOCK_DOMAIN,
                success=False,
                execution_time_ms=execution_time,
                message=f"Failed to block domain: {str(e)}"
            )


class ProcessManager:
    """Manages process termination for malicious software"""
    
    @staticmethod
    async def kill_process(process_name: str, machine_id: Optional[str] = None) -> ActionResult:
        """Terminate suspicious process"""
        start_time = datetime.now()
        
        try:
            killed_count = 0
            
            # Find and kill processes
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'].lower() == process_name.lower():
                        proc.kill()
                        killed_count += 1
                        print(f"⚡ KILLED PROCESS: {process_name} (PID: {proc.info['pid']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return ActionResult(
                action=ResponseAction.KILL_PROCESS,
                success=killed_count > 0,
                execution_time_ms=execution_time,
                message=f"Killed {killed_count} instance(s) of {process_name}",
                details={"process_name": process_name, "killed_count": killed_count}
            )
        except Exception as e:
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            return ActionResult(
                action=ResponseAction.KILL_PROCESS,
                success=False,
                execution_time_ms=execution_time,
                message=f"Failed to kill process: {str(e)}"
            )


class PrivilegeManager:
    """Manages user privilege revocation"""
    
    @staticmethod
    async def revoke_privileges(username: str, privileges: List[str]) -> ActionResult:
        """Revoke user privileges"""
        start_time = datetime.now()
        
        try:
            # In production: Interface with Active Directory or local user management
            print(f"🔓 REVOKED PRIVILEGES: {username} - {', '.join(privileges)}")
            
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return ActionResult(
                action=ResponseAction.REVOKE_PRIVILEGES,
                success=True,
                execution_time_ms=execution_time,
                message=f"Revoked privileges for {username}",
                details={"username": username, "privileges": privileges}
            )
        except Exception as e:
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            return ActionResult(
                action=ResponseAction.REVOKE_PRIVILEGES,
                success=False,
                execution_time_ms=execution_time,
                message=f"Failed to revoke privileges: {str(e)}"
            )
    
    @staticmethod
    async def lock_account(username: str, duration_minutes: Optional[int] = 30) -> ActionResult:
        """Lock user account"""
        start_time = datetime.now()
        
        try:
            # Lock account via AD or local security policy
            print(f"🔒 LOCKED ACCOUNT: {username} for {duration_minutes} minutes")
            
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return ActionResult(
                action=ResponseAction.LOCK_ACCOUNT,
                success=True,
                execution_time_ms=execution_time,
                message=f"Account {username} locked for {duration_minutes} minutes",
                details={"username": username, "duration_minutes": duration_minutes}
            )
        except Exception as e:
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            return ActionResult(
                action=ResponseAction.LOCK_ACCOUNT,
                success=False,
                execution_time_ms=execution_time,
                message=f"Failed to lock account: {str(e)}"
            )


class ForensicsCollector:
    """Collects forensic data from threat events"""
    
    @staticmethod
    async def capture_forensics(machine_id: str, event_id: str) -> ActionResult:
        """Capture forensic data"""
        start_time = datetime.now()
        
        try:
            forensics_data = {
                "memory_dump": f"mem_dump_{machine_id}_{event_id}.dmp",
                "process_list": [p.info for p in psutil.process_iter(['pid', 'name', 'username'])],
                "network_connections": [
                    {"local": f"{conn.laddr.ip}:{conn.laddr.port}",
                     "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                     "status": conn.status}
                    for conn in psutil.net_connections() if conn.status == 'ESTABLISHED'
                ],
                "system_info": {
                    "hostname": socket.gethostname(),
                    "platform": psutil.os.name,
                    "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat()
                }
            }
            
            print(f"📸 CAPTURED FORENSICS: {machine_id} - Event {event_id}")
            
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return ActionResult(
                action=ResponseAction.CAPTURE_FORENSICS,
                success=True,
                execution_time_ms=execution_time,
                message="Forensic data captured successfully",
                details=forensics_data
            )
        except Exception as e:
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            return ActionResult(
                action=ResponseAction.CAPTURE_FORENSICS,
                success=False,
                execution_time_ms=execution_time,
                message=f"Failed to capture forensics: {str(e)}"
            )


class AutomatedResponseSystem:
    """Main automated threat response orchestrator"""
    
    def __init__(self):
        self.machine_isolation = MachineIsolationEngine()
        self.firewall = FirewallController()
        self.process_manager = ProcessManager()
        self.privilege_manager = PrivilegeManager()
        self.forensics = ForensicsCollector()
        
        # Response workflows by threat level
        self.workflows = self._initialize_workflows()
    
    def _initialize_workflows(self) -> Dict[ThreatLevel, List[ResponseAction]]:
        """Define automated response workflows"""
        return {
            ThreatLevel.CRITICAL: [
                ResponseAction.ISOLATE_MACHINE,
                ResponseAction.KILL_PROCESS,
                ResponseAction.CAPTURE_FORENSICS,
                ResponseAction.LOCK_ACCOUNT,
                ResponseAction.ALERT_ADMIN,
            ],
            ThreatLevel.DANGEROUS: [
                ResponseAction.QUARANTINE_EMAIL,
                ResponseAction.BLOCK_SENDER,
                ResponseAction.BLOCK_IP,
                ResponseAction.REVOKE_PRIVILEGES,
                ResponseAction.ALERT_ADMIN,
            ],
            ThreatLevel.SUSPICIOUS: [
                ResponseAction.QUARANTINE_EMAIL,
                ResponseAction.BLOCK_SENDER,
                ResponseAction.ALERT_ADMIN,
            ],
            ThreatLevel.SAFE: []
        }
    
    async def respond(self, threat_event: ThreatEvent) -> List[ActionResult]:
        """Execute automated response workflow"""
        workflow_start = datetime.now()
        results = []
        
        # Get actions for threat level
        actions = self.workflows.get(threat_event.threat_level, [])
        
        print(f"\n🚨 THREAT DETECTED: {threat_event.threat_type.upper()} - {threat_event.threat_level.value.upper()}")
        print(f"   Score: {threat_event.threat_score}/100")
        print(f"   Executing {len(actions)} containment actions...")
        
        # Execute actions in parallel where possible
        tasks = []
        
        for action in actions:
            task = self._execute_action(action, threat_event)
            tasks.append(task)
        
        # Wait for all actions to complete
        results = await asyncio.gather(*tasks)
        
        # Calculate total execution time
        total_time = int((datetime.now() - workflow_start).total_seconds() * 1000)
        
        success_count = sum(1 for r in results if r.success)
        
        print(f"\n✅ RESPONSE COMPLETE: {success_count}/{len(results)} actions successful in {total_time}ms")
        
        return results
    
    async def _execute_action(self, action: ResponseAction, threat_event: ThreatEvent) -> ActionResult:
        """Execute a single response action"""
        
        if action == ResponseAction.ISOLATE_MACHINE:
            if threat_event.source_machine:
                return await self.machine_isolation.isolate(
                    threat_event.source_machine,
                    f"{threat_event.threat_type} - Score: {threat_event.threat_score}"
                )
        
        elif action == ResponseAction.BLOCK_IP:
            if threat_event.source_ip:
                return await self.firewall.block_ip(threat_event.source_ip)
        
        elif action == ResponseAction.BLOCK_DOMAIN:
            if threat_event.details.get('domain'):
                return await self.firewall.block_domain(threat_event.details['domain'])
        
        elif action == ResponseAction.KILL_PROCESS:
            if threat_event.details.get('process_name'):
                return await self.process_manager.kill_process(
                    threat_event.details['process_name'],
                    threat_event.source_machine
                )
        
        elif action == ResponseAction.REVOKE_PRIVILEGES:
            if threat_event.source_user:
                return await self.privilege_manager.revoke_privileges(
                    threat_event.source_user,
                    ["admin", "remote_access"]
                )
        
        elif action == ResponseAction.LOCK_ACCOUNT:
            if threat_event.source_user:
                return await self.privilege_manager.lock_account(threat_event.source_user)
        
        elif action == ResponseAction.CAPTURE_FORENSICS:
            if threat_event.source_machine:
                return await self.forensics.capture_forensics(
                    threat_event.source_machine,
                    threat_event.event_id
                )
        
        elif action == ResponseAction.ALERT_ADMIN:
            return ActionResult(
                action=ResponseAction.ALERT_ADMIN,
                success=True,
                execution_time_ms=10,
                message="Admin alert sent",
                details={"alert_type": "threat_detected", "threat_level": threat_event.threat_level.value}
            )
        
        # Default response for unhandled actions
        return ActionResult(
            action=action,
            success=False,
            execution_time_ms=0,
            message=f"Action {action.value} not implemented for this threat"
        )
