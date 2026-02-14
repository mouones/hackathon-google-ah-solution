"""
Sentinel Shield - Network Segmentation Controller
VLAN-based department isolation with micro-segmentation and zero-trust policies
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
from datetime import datetime


class Department(Enum):
    """Department types for network segmentation"""
    MARKETING = "marketing"
    SALES = "sales"
    DEVELOPMENT = "development"
    HR = "hr"
    EXECUTIVE = "executive"
    IT_SECURITY = "it_security"
    FINANCE = "finance"
    OPERATIONS = "operations"
    GUEST = "guest"


class FirewallAction(Enum):
    """Firewall rule actions"""
    ALLOW = "allow"
    DENY = "deny"
    LOG = "log"
    ALERT = "alert"


@dataclass
class VLANConfig:
    """VLAN configuration for department"""
    vlan_id: int
    department: Department
    subnet: str  # e.g., "10.10.10.0/24"
    gateway: str
    dns_servers: List[str]
    allowed_protocols: List[str] = field(default_factory=list)
    blocked_ports: List[int] = field(default_factory=list)
    max_devices: int = 254


@dataclass
class FirewallRule:
    """Firewall rule definition"""
    rule_id: str
    name: str
    source_vlan: int
    destination_vlan: Optional[int]
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: str = "any"  # tcp, udp, icmp, any
    port: Optional[int] = None
    action: FirewallAction = FirewallAction.DENY
    priority: int = 100
    enabled: bool = True
    description: str = ""


@dataclass
class AccessPolicy:
    """Access control policy"""
    policy_id: str
    name: str
    source_department: Department
    target_department: Department
    allowed_services: List[str]  # e.g., ["http", "https", "email"]
    time_restrictions: Optional[Dict] = None  # Business hours only
    requires_mfa: bool = False


@dataclass
class NetworkDevice:
    """Network device (endpoint)"""
    mac_address: str
    ip_address: str
    hostname: str
    department: Department
    vlan_id: int
    device_type: str  # workstation, server, printer, etc.
    user: Optional[str] = None
    last_seen: datetime = field(default_factory=datetime.now)
    is_isolated: bool = False


class NetworkSegmentationController:
    """Main network segmentation controller"""
    
    def __init__(self):
        self.vlans = self._initialize_vlans()
        self.firewall_rules = self._initialize_firewall_rules()
        self.access_policies = self._initialize_access_policies()
        self.devices: Dict[str, NetworkDevice] = {}
        self.quarantine_vlan = 999  # Isolated VLAN for compromised devices
    
    def _initialize_vlans(self) -> Dict[Department, VLANConfig]:
        """Initialize department VLANs"""
        return {
            Department.MARKETING: VLANConfig(
                vlan_id=10,
                department=Department.MARKETING,
                subnet="10.10.10.0/24",
                gateway="10.10.10.1",
                dns_servers=["10.0.0.53"],
                allowed_protocols=["http", "https", "email"],
                blocked_ports=[22, 23, 3389, 445, 139]  # SSH, Telnet, RDP, SMB
            ),
            Department.SALES: VLANConfig(
                vlan_id=20,
                department=Department.SALES,
                subnet="10.10.20.0/24",
                gateway="10.10.20.1",
                dns_servers=["10.0.0.53"],
                allowed_protocols=["http", "https", "email", "crm"],
                blocked_ports=[22, 23, 3389, 445, 139, 1433, 3306]  # + Database ports
            ),
            Department.DEVELOPMENT: VLANConfig(
                vlan_id=30,
                department=Department.DEVELOPMENT,
                subnet="10.10.30.0/24",
                gateway="10.10.30.1",
                dns_servers=["10.0.0.53"],
                allowed_protocols=["http", "https", "ssh", "git"],
                blocked_ports=[23, 445, 139]  # Only Telnet and SMB blocked
            ),
            Department.HR: VLANConfig(
                vlan_id=40,
                department=Department.HR,
                subnet="10.10.40.0/24",
                gateway="10.10.40.1",
                dns_servers=["10.0.0.53"],
                allowed_protocols=["http", "https", "email"],
                blocked_ports=[22, 23, 3389, 445, 139, 1433, 3306, 5432]  # All admin ports
            ),
            Department.EXECUTIVE: VLANConfig(
                vlan_id=50,
                department=Department.EXECUTIVE,
                subnet="10.10.50.0/24",
                gateway="10.10.50.1",
                dns_servers=["10.0.0.53"],
                allowed_protocols=["http", "https", "email", "vpn"],
                blocked_ports=[22, 23, 445, 139]
            ),
            Department.IT_SECURITY: VLANConfig(
                vlan_id=60,
                department=Department.IT_SECURITY,
                subnet="10.10.60.0/24",
                gateway="10.10.60.1",
                dns_servers=["10.0.0.53"],
                allowed_protocols=["all"],  # IT Security has full access
                blocked_ports=[]
            ),
            Department.FINANCE: VLANConfig(
                vlan_id=70,
                department=Department.FINANCE,
                subnet="10.10.70.0/24",
                gateway="10.10.70.1",
                dns_servers=["10.0.0.53"],
                allowed_protocols=["http", "https", "email", "erp"],
                blocked_ports=[22, 23, 3389, 445, 139]
            ),
            Department.GUEST: VLANConfig(
                vlan_id=90,
                department=Department.GUEST,
                subnet="10.10.90.0/24",
                gateway="10.10.90.1",
                dns_servers=["8.8.8.8", "8.8.4.4"],  # Public DNS only
                allowed_protocols=["http", "https"],
                blocked_ports=list(range(1, 1024)) + [3389, 445, 139]  # Block all privileged ports
            )
        }
    
    def _initialize_firewall_rules(self) -> List[FirewallRule]:
        """Initialize default firewall rules"""
        rules = [
            # Rule 1: Deny all by default
            FirewallRule(
                rule_id="FW-001",
                name="Default Deny All",
                source_vlan=0,  # 0 means any
                destination_vlan=0,
                action=FirewallAction.DENY,
                priority=999,
                description="Default deny rule - must be overridden by allow rules"
            ),
            
            # Rule 2: Allow Marketing -> Internet (HTTP/HTTPS only)
            FirewallRule(
                rule_id="FW-010",
                name="Marketing Internet Access",
                source_vlan=10,
                destination_vlan=None,  # None means external
                protocol="tcp",
                port=443,
                action=FirewallAction.ALLOW,
                priority=10,
                description="Allow Marketing HTTPS to internet"
            ),
            
            # Rule 3: Block Marketing -> Sales
            FirewallRule(
                rule_id="FW-011",
                name="Block Marketing to Sales",
                source_vlan=10,
                destination_vlan=20,
                action=FirewallAction.DENY,
                priority=5,
                description="Prevent cross-department lateral movement"
            ),
            
            # Rule 4: Block Sales -> Development
            FirewallRule(
                rule_id="FW-021",
                name="Block Sales to Development",
                source_vlan=20,
                destination_vlan=30,
                action=FirewallAction.DENY,
                priority=5,
                description="Protect development environment"
            ),
            
            # Rule 5: Block all departments -> Finance (except IT Security)
            FirewallRule(
                rule_id="FW-070",
                name="Isolate Finance Department",
                source_vlan=0,  # Any VLAN
                destination_vlan=70,
                action=FirewallAction.DENY,
                priority=3,
                description="Finance VLAN is isolated"
            ),
            
            # Rule 6: Allow IT Security -> All
            FirewallRule(
                rule_id="FW-060",
                name="IT Security Full Access",
                source_vlan=60,
                destination_vlan=0,
                action=FirewallAction.ALLOW,
                priority=1,
                description="IT Security can access all VLANs"
            ),
            
            # Rule 7: Block reverse shells (common ports)
            FirewallRule(
                rule_id="FW-900",
                name="Block Reverse Shell Ports",
                source_vlan=0,
                destination_vlan=None,
                protocol="tcp",
                port=4444,  # Common Metasploit port
                action=FirewallAction.ALERT,
                priority=2,
                description="Alert on reverse shell attempts"
            ),
            
            # Rule 8: Block Guest -> Internal
            FirewallRule(
                rule_id="FW-090",
                name="Block Guest to Internal",
                source_vlan=90,
                destination_vlan=0,
                action=FirewallAction.DENY,
                priority=3,
                description="Guest network cannot access internal resources"
            )
        ]
        
        # Add blocked ports rules for each department
        for dept, vlan_config in self.vlans.items():
            if vlan_config.blocked_ports:
                for port in vlan_config.blocked_ports:
                    rules.append(FirewallRule(
                        rule_id=f"FW-{vlan_config.vlan_id:03d}-{port}",
                        name=f"Block {dept.value} Port {port}",
                        source_vlan=vlan_config.vlan_id,
                        destination_vlan=None,
                        protocol="tcp",
                        port=port,
                        action=FirewallAction.DENY,
                        priority=5,
                        description=f"Block dangerous port {port} for {dept.value}"
                    ))
        
        return rules
    
    def _initialize_access_policies(self) -> List[AccessPolicy]:
        """Initialize zero-trust access policies"""
        return [
            AccessPolicy(
                policy_id="POL-001",
                name="Marketing Email Access",
                source_department=Department.MARKETING,
                target_department=Department.IT_SECURITY,
                allowed_services=["email", "web"],
                requires_mfa=False
            ),
            AccessPolicy(
                policy_id="POL-002",
                name="Sales CRM Access",
                source_department=Department.SALES,
                target_department=Department.IT_SECURITY,
                allowed_services=["email", "web", "crm"],
                requires_mfa=True
            ),
            AccessPolicy(
                policy_id="POL-003",
                name="Development Git Access",
                source_department=Department.DEVELOPMENT,
                target_department=Department.IT_SECURITY,
                allowed_services=["git", "ssh", "web"],
                requires_mfa=True
            ),
            AccessPolicy(
                policy_id="POL-004",
                name="HR Sensitive Data Access",
                source_department=Department.HR,
                target_department=Department.IT_SECURITY,
                allowed_services=["hrms", "email"],
                requires_mfa=True,
                time_restrictions={"business_hours_only": True}
            )
        ]
    
    def assign_device(
        self,
        mac_address: str,
        department: Department,
        device_type: str,
        hostname: str,
        user: Optional[str] = None
    ) -> NetworkDevice:
        """Assign device to department VLAN"""
        
        vlan_config = self.vlans[department]
        
        # Generate IP from subnet
        network = ipaddress.IPv4Network(vlan_config.subnet)
        # Simple IP assignment (in production, use DHCP integration)
        ip_address = str(network.network_address + len(self.devices) + 10)
        
        device = NetworkDevice(
            mac_address=mac_address,
            ip_address=ip_address,
            hostname=hostname,
            department=department,
            vlan_id=vlan_config.vlan_id,
            device_type=device_type,
            user=user
        )
        
        self.devices[mac_address] = device
        
        print(f"✅ Assigned {hostname} to {department.value} VLAN {vlan_config.vlan_id} - IP: {ip_address}")
        
        return device
    
    def isolate_device(self, mac_address: str, reason: str) -> bool:
        """Move device to quarantine VLAN"""
        device = self.devices.get(mac_address)
        
        if not device:
            return False
        
        # Move to quarantine VLAN
        device.vlan_id = self.quarantine_vlan
        device.is_isolated = True
        
        print(f"🔒 ISOLATED: {device.hostname} moved to quarantine VLAN {self.quarantine_vlan}")
        print(f"   Reason: {reason}")
        
        return True
    
    def check_access(
        self,
        source_mac: str,
        destination_ip: str,
        port: int,
        protocol: str = "tcp"
    ) -> Tuple[bool, str]:
        """Check if access is allowed by firewall rules"""
        
        source_device = self.devices.get(source_mac)
        if not source_device:
            return False, "Unknown source device"
        
        if source_device.is_isolated:
            return False, "Source device is quarantined"
        
        # Find applicable firewall rules (sorted by priority)
        applicable_rules = [
            rule for rule in self.firewall_rules
            if rule.enabled and
            (rule.source_vlan == 0 or rule.source_vlan == source_device.vlan_id) and
            (not rule.port or rule.port == port) and
            (rule.protocol == "any" or rule.protocol == protocol)
        ]
        
        # Sort by priority (lower = higher priority)
        applicable_rules.sort(key=lambda r: r.priority)
        
        # Check first matching rule
        for rule in applicable_rules:
            if rule.action == FirewallAction.ALLOW:
                return True, f"Allowed by rule {rule.rule_id}: {rule.name}"
            elif rule.action == FirewallAction.DENY:
                return False, f"Blocked by rule {rule.rule_id}: {rule.name}"
            elif rule.action == FirewallAction.ALERT:
                print(f"⚠️ ALERT: Suspicious traffic from {source_device.hostname} to port {port}")
                return False, f"Alerted and blocked by rule {rule.rule_id}"
        
        # Default deny
        return False, "Default deny - no matching allow rule"
    
    def detect_lateral_movement(self, source_mac: str, attempts: List[str]) -> bool:
        """Detect lateral movement attempts"""
        
        if len(attempts) > 5:  # More than 5 different targets
            device = self.devices.get(source_mac)
            if device:
                print(f"🚨 LATERAL MOVEMENT DETECTED: {device.hostname} attempted {len(attempts)} connections")
                self.isolate_device(source_mac, "Suspected lateral movement attack")
                return True
        
        return False
    
    def enforce_zero_trust(self, source_mac: str, service: str) -> bool:
        """Enforce zero-trust policy"""
        
        source_device = self.devices.get(source_mac)
        if not source_device:
            return False
        
        # Find applicable policy
        for policy in self.access_policies:
            if policy.source_department == source_device.department:
                if service in policy.allowed_services:
                    if policy.requires_mfa:
                        # In production: verify MFA token
                        print(f"🔐 MFA required for {source_device.user} to access {service}")
                    return True
        
        return False
    
    def get_network_summary(self) -> Dict:
        """Get network segmentation summary"""
        return {
            "total_vlans": len(self.vlans),
            "total_devices": len(self.devices),
            "isolated_devices": sum(1 for d in self.devices.values() if d.is_isolated),
            "active_rules": sum(1 for r in self.firewall_rules if r.enabled),
            "departments": {dept.value: vlan.vlan_id for dept, vlan in self.vlans.items()},
            "device_distribution": {
                dept.value: sum(1 for d in self.devices.values() if d.department == dept)
                for dept in Department
            }
        }
