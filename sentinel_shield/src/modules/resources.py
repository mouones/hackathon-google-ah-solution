"""
Sentinel Shield - Resources & Integrations Reference
Comprehensive list of all data sources, APIs, tools, and potential partners
"""

# =============================================================================
# THREAT INTELLIGENCE FEEDS
# =============================================================================

THREAT_INTEL_FEEDS = {
    "urlhaus": {
        "name": "URLhaus by Abuse.ch",
        "url": "https://urlhaus.abuse.ch/",
        "type": "Malware URLs",
        "format": "CSV, JSON, API",
        "update_frequency": "Every 5 minutes",
        "license": "Free",
        "integration_status": "active"
    },
    "phishtank": {
        "name": "PhishTank",
        "url": "https://phishtank.org/",
        "type": "Phishing URLs",
        "format": "CSV, JSON, XML",
        "update_frequency": "Hourly",
        "license": "Free (API key required)",
        "integration_status": "active"
    },
    "openphish": {
        "name": "OpenPhish",
        "url": "https://openphish.com/",
        "type": "Phishing URLs",
        "format": "Text, JSON",
        "update_frequency": "Every 12 hours",
        "license": "Free (Community) / Paid (Premium)",
        "integration_status": "active"
    },
    "malwarebazaar": {
        "name": "MalwareBazaar",
        "url": "https://bazaar.abuse.ch/",
        "type": "Malware samples & hashes",
        "format": "API, CSV",
        "update_frequency": "Real-time",
        "license": "Free",
        "integration_status": "active"
    },
    "threatfox": {
        "name": "ThreatFox",
        "url": "https://threatfox.abuse.ch/",
        "type": "IOCs (IPs, domains, URLs)",
        "format": "API, JSON, CSV",
        "update_frequency": "Real-time",
        "license": "Free",
        "integration_status": "active"
    },
    "feodo_tracker": {
        "name": "Feodo Tracker",
        "url": "https://feodotracker.abuse.ch/",
        "type": "Botnet C2 servers",
        "format": "CSV, JSON",
        "update_frequency": "Daily",
        "license": "Free",
        "integration_status": "active"
    },
    "sslbl": {
        "name": "SSL Blacklist",
        "url": "https://sslbl.abuse.ch/",
        "type": "Malicious SSL certificates",
        "format": "CSV",
        "update_frequency": "Daily",
        "license": "Free",
        "integration_status": "active"
    },
    "alienvault_otx": {
        "name": "AlienVault OTX",
        "url": "https://otx.alienvault.com/",
        "type": "Threat pulses, IOCs",
        "format": "API",
        "update_frequency": "Real-time",
        "license": "Free",
        "integration_status": "active"
    },
    "emergingthreats": {
        "name": "Emerging Threats",
        "url": "https://rules.emergingthreats.net/",
        "type": "Suricata/Snort rules",
        "format": "Rules files",
        "update_frequency": "Daily",
        "license": "Free (Open) / Paid (Pro)",
        "integration_status": "planned"
    },
    "spamhaus": {
        "name": "Spamhaus",
        "url": "https://www.spamhaus.org/",
        "type": "Spam IPs, domains",
        "format": "DNSBL, API",
        "update_frequency": "Real-time",
        "license": "Free (limited) / Paid",
        "integration_status": "active"
    },
    "blocklist_de": {
        "name": "Blocklist.de",
        "url": "https://www.blocklist.de/",
        "type": "Attack IPs",
        "format": "Text, API",
        "update_frequency": "Hourly",
        "license": "Free",
        "integration_status": "active"
    },
    "cinsscore": {
        "name": "CINS Score",
        "url": "https://cinsscore.com/",
        "type": "Malicious IPs",
        "format": "Text",
        "update_frequency": "Daily",
        "license": "Free",
        "integration_status": "active"
    },
    "botvrij": {
        "name": "Botvrij.eu",
        "url": "https://botvrij.eu/",
        "type": "IOCs, blocklists",
        "format": "CSV, STIX",
        "update_frequency": "Daily",
        "license": "Free",
        "integration_status": "planned"
    }
}

# =============================================================================
# SECURITY APIS
# =============================================================================

SECURITY_APIS = {
    "virustotal": {
        "name": "VirusTotal",
        "url": "https://www.virustotal.com/",
        "purpose": "File/URL scanning with 70+ AV engines",
        "pricing": "Free (limited) / Enterprise",
        "integration_status": "active"
    },
    "hybrid_analysis": {
        "name": "Hybrid Analysis",
        "url": "https://www.hybrid-analysis.com/",
        "purpose": "Free malware sandbox",
        "pricing": "Free / Enterprise",
        "integration_status": "active"
    },
    "any_run": {
        "name": "ANY.RUN",
        "url": "https://any.run/",
        "purpose": "Interactive malware sandbox",
        "pricing": "Free (limited) / Paid",
        "integration_status": "planned"
    },
    "joe_sandbox": {
        "name": "Joe Sandbox",
        "url": "https://www.joesandbox.com/",
        "purpose": "Deep malware analysis",
        "pricing": "Paid",
        "integration_status": "future_partner"
    },
    "urlscan": {
        "name": "URLScan.io",
        "url": "https://urlscan.io/",
        "purpose": "Website scanning & screenshots",
        "pricing": "Free / Paid",
        "integration_status": "active"
    },
    "shodan": {
        "name": "Shodan",
        "url": "https://www.shodan.io/",
        "purpose": "Internet-connected device search",
        "pricing": "Free (limited) / Paid",
        "integration_status": "active"
    },
    "censys": {
        "name": "Censys",
        "url": "https://censys.io/",
        "purpose": "Internet asset discovery",
        "pricing": "Free (limited) / Enterprise",
        "integration_status": "planned"
    },
    "hibp": {
        "name": "Have I Been Pwned",
        "url": "https://haveibeenpwned.com/",
        "purpose": "Breach detection",
        "pricing": "Free API / Enterprise",
        "integration_status": "active"
    },
    "dehashed": {
        "name": "Dehashed",
        "url": "https://dehashed.com/",
        "purpose": "Leaked credential search",
        "pricing": "Paid",
        "integration_status": "planned"
    },
    "greynoise": {
        "name": "GreyNoise",
        "url": "https://www.greynoise.io/",
        "purpose": "Internet scanner classification",
        "pricing": "Free (limited) / Paid",
        "integration_status": "planned"
    },
    "abuseipdb": {
        "name": "AbuseIPDB",
        "url": "https://www.abuseipdb.com/",
        "purpose": "IP reputation checking",
        "pricing": "Free / Paid",
        "integration_status": "active"
    },
    "ipqualityscore": {
        "name": "IPQualityScore",
        "url": "https://www.ipqualityscore.com/",
        "purpose": "Fraud/proxy detection",
        "pricing": "Free (limited) / Paid",
        "integration_status": "planned"
    }
}

# =============================================================================
# ML DATASETS
# =============================================================================

ML_DATASETS = {
    "nazario_phishing": {
        "name": "Nazario Phishing Corpus",
        "source": "Jose Nazario",
        "type": "Phishing emails",
        "size": "4,500+ emails",
        "use_case": "Phishing detection training"
    },
    "enron_email": {
        "name": "Enron Email Dataset",
        "source": "CMU",
        "type": "Legitimate emails",
        "size": "500,000+ emails",
        "use_case": "Legitimate email baseline"
    },
    "kaggle_spam": {
        "name": "SMS Spam Collection",
        "source": "Kaggle",
        "type": "SMS messages",
        "size": "5,500+ messages",
        "use_case": "Smishing detection"
    },
    "kaggle_phishing": {
        "name": "Phishing Website Dataset",
        "source": "Kaggle",
        "type": "Website features",
        "size": "11,000+ samples",
        "use_case": "URL classification"
    },
    "apwg_dataset": {
        "name": "APWG eCrime Dataset",
        "source": "Anti-Phishing Working Group",
        "type": "Phishing URLs",
        "size": "Updated monthly",
        "use_case": "Phishing URL detection"
    },
    "malware_traffic": {
        "name": "Malware Traffic Analysis",
        "source": "malware-traffic-analysis.net",
        "type": "PCAP files",
        "size": "1000+ samples",
        "use_case": "Network threat detection"
    },
    "malimg": {
        "name": "MalImg Dataset",
        "source": "Vision Research Lab",
        "type": "Malware visualization",
        "size": "9,000+ images",
        "use_case": "Visual malware classification"
    },
    "ember": {
        "name": "EMBER Dataset",
        "source": "Endgame/Elastic",
        "type": "PE file features",
        "size": "1.1M samples",
        "use_case": "Malware classification"
    }
}

# =============================================================================
# YARA RULES SOURCES
# =============================================================================

YARA_SOURCES = {
    "yara_rules_repo": {
        "name": "YARA-Rules Repository",
        "url": "https://github.com/Yara-Rules/rules",
        "type": "Community rules",
        "categories": ["malware", "packers", "crypto", "exploits"]
    },
    "signature_base": {
        "name": "Signature-Base",
        "url": "https://github.com/Neo23x0/signature-base",
        "type": "Curated rules",
        "categories": ["apt", "malware", "webshells", "exploits"]
    },
    "bartblaze_rules": {
        "name": "Bartblaze YARA",
        "url": "https://github.com/bartblaze/Yara-rules",
        "type": "Malware rules",
        "categories": ["ransomware", "stealers", "rats"]
    },
    "inquest_rules": {
        "name": "InQuest YARA",
        "url": "https://github.com/InQuest/yara-rules",
        "type": "Document analysis",
        "categories": ["office", "pdf", "rtf"]
    },
    "fireeye_rules": {
        "name": "FireEye YARA",
        "url": "https://github.com/fireeye/red_team_tool_countermeasures",
        "type": "APT detection",
        "categories": ["apt", "tools", "techniques"]
    },
    "elastic_rules": {
        "name": "Elastic Detection Rules",
        "url": "https://github.com/elastic/detection-rules",
        "type": "Detection rules",
        "categories": ["endpoint", "network", "cloud"]
    }
}

# =============================================================================
# OPEN SOURCE TOOLS TO INTEGRATE
# =============================================================================

OPENSOURCE_TOOLS = {
    "cuckoo": {
        "name": "Cuckoo Sandbox",
        "url": "https://cuckoosandbox.org/",
        "purpose": "Automated malware analysis",
        "integration": "Local sandbox deployment"
    },
    "thehive": {
        "name": "TheHive",
        "url": "https://thehive-project.org/",
        "purpose": "Security incident response platform",
        "integration": "Alert escalation"
    },
    "cortex": {
        "name": "Cortex",
        "url": "https://github.com/TheHive-Project/Cortex",
        "purpose": "Observable analysis engine",
        "integration": "IOC enrichment"
    },
    "misp": {
        "name": "MISP",
        "url": "https://www.misp-project.org/",
        "purpose": "Threat intelligence sharing",
        "integration": "IOC sync"
    },
    "opencti": {
        "name": "OpenCTI",
        "url": "https://www.opencti.io/",
        "purpose": "Cyber threat intelligence platform",
        "integration": "Threat data aggregation"
    },
    "zeek": {
        "name": "Zeek (Bro)",
        "url": "https://zeek.org/",
        "purpose": "Network security monitoring",
        "integration": "Network analysis"
    },
    "suricata": {
        "name": "Suricata",
        "url": "https://suricata.io/",
        "purpose": "IDS/IPS",
        "integration": "Network intrusion detection"
    },
    "wazuh": {
        "name": "Wazuh",
        "url": "https://wazuh.com/",
        "purpose": "SIEM, XDR",
        "integration": "Endpoint & log analysis"
    },
    "osquery": {
        "name": "OSQuery",
        "url": "https://osquery.io/",
        "purpose": "Endpoint visibility",
        "integration": "System querying"
    },
    "velociraptor": {
        "name": "Velociraptor",
        "url": "https://docs.velociraptor.app/",
        "purpose": "DFIR tool",
        "integration": "Incident response"
    },
    "yara": {
        "name": "YARA",
        "url": "https://virustotal.github.io/yara/",
        "purpose": "Pattern matching",
        "integration": "Malware detection"
    },
    "oletools": {
        "name": "OLETools",
        "url": "https://github.com/decalage2/oletools",
        "purpose": "Office document analysis",
        "integration": "Attachment scanning"
    },
    "peframe": {
        "name": "PEframe",
        "url": "https://github.com/guelfoweb/peframe",
        "purpose": "PE file analysis",
        "integration": "Executable analysis"
    },
    "malwoverview": {
        "name": "Malwoverview",
        "url": "https://github.com/alexandreborges/malwoverview",
        "purpose": "Threat hunting",
        "integration": "Sample triage"
    }
}

# =============================================================================
# POTENTIAL PARTNERS & COMMERCIAL INTEGRATIONS
# =============================================================================

POTENTIAL_PARTNERS = {
    "anydesk": {
        "name": "AnyDesk",
        "url": "https://anydesk.com/",
        "purpose": "Remote desktop for incident response",
        "partnership_type": "Technology Partner",
        "use_case": "Remote malware analysis & remediation"
    },
    "teamviewer": {
        "name": "TeamViewer",
        "url": "https://www.teamviewer.com/",
        "purpose": "Remote access",
        "partnership_type": "Technology Partner",
        "use_case": "Remote support for security incidents"
    },
    "crowdstrike": {
        "name": "CrowdStrike",
        "url": "https://www.crowdstrike.com/",
        "purpose": "EDR/XDR",
        "partnership_type": "Integration Partner",
        "use_case": "Advanced endpoint protection"
    },
    "sentinelone": {
        "name": "SentinelOne",
        "url": "https://www.sentinelone.com/",
        "purpose": "AI-powered endpoint security",
        "partnership_type": "Integration Partner",
        "use_case": "Endpoint threat response"
    },
    "palo_alto": {
        "name": "Palo Alto Networks",
        "url": "https://www.paloaltonetworks.com/",
        "purpose": "Firewall, WildFire sandbox",
        "partnership_type": "Integration Partner",
        "use_case": "Network security"
    },
    "fortinet": {
        "name": "Fortinet",
        "url": "https://www.fortinet.com/",
        "purpose": "Firewall, FortiSandbox",
        "partnership_type": "Integration Partner",
        "use_case": "Network security"
    },
    "recorded_future": {
        "name": "Recorded Future",
        "url": "https://www.recordedfuture.com/",
        "purpose": "Threat intelligence",
        "partnership_type": "Data Partner",
        "use_case": "Premium threat feeds"
    },
    "mandiant": {
        "name": "Mandiant (Google)",
        "url": "https://www.mandiant.com/",
        "purpose": "Threat intelligence, IR",
        "partnership_type": "Service Partner",
        "use_case": "Incident response support"
    },
    "knowbe4": {
        "name": "KnowBe4",
        "url": "https://www.knowbe4.com/",
        "purpose": "Security awareness training",
        "partnership_type": "Integration Partner",
        "use_case": "Enhanced training content"
    },
    "proofpoint": {
        "name": "Proofpoint",
        "url": "https://www.proofpoint.com/",
        "purpose": "Email security",
        "partnership_type": "Competitor/Integration",
        "use_case": "Threat data sharing"
    },
    "cofense": {
        "name": "Cofense",
        "url": "https://cofense.com/",
        "purpose": "Phishing defense",
        "partnership_type": "Integration Partner",
        "use_case": "Phishing simulation"
    },
    "abnormal_security": {
        "name": "Abnormal Security",
        "url": "https://abnormalsecurity.com/",
        "purpose": "BEC protection",
        "partnership_type": "Competitor/Reference",
        "use_case": "BEC detection techniques"
    }
}

# =============================================================================
# EMAIL SERVICE INTEGRATIONS
# =============================================================================

EMAIL_INTEGRATIONS = {
    "microsoft_365": {
        "name": "Microsoft 365",
        "api": "Microsoft Graph API",
        "features": ["Email reading", "Mailbox access", "Security Center"],
        "auth": "OAuth 2.0",
        "integration_status": "active"
    },
    "google_workspace": {
        "name": "Google Workspace",
        "api": "Gmail API, Admin SDK",
        "features": ["Email reading", "Quarantine", "DLP"],
        "auth": "OAuth 2.0",
        "integration_status": "active"
    },
    "exchange_on_prem": {
        "name": "Exchange On-Premise",
        "api": "EWS, PowerShell",
        "features": ["Transport rules", "Journaling"],
        "auth": "NTLM, Basic",
        "integration_status": "active"
    },
    "postmark": {
        "name": "Postmark",
        "api": "REST API",
        "features": ["Inbound parsing", "Webhook"],
        "auth": "API Key",
        "integration_status": "planned"
    },
    "sendgrid": {
        "name": "SendGrid",
        "api": "REST API",
        "features": ["Inbound parse", "Event webhook"],
        "auth": "API Key",
        "integration_status": "planned"
    },
    "mailgun": {
        "name": "Mailgun",
        "api": "REST API",
        "features": ["Routes", "Inbound"],
        "auth": "API Key",
        "integration_status": "planned"
    }
}

# =============================================================================
# SIEM & LOG INTEGRATIONS
# =============================================================================

SIEM_INTEGRATIONS = {
    "splunk": {
        "name": "Splunk",
        "method": "HTTP Event Collector (HEC)",
        "format": "JSON",
        "features": ["Real-time alerts", "Dashboards"]
    },
    "elastic": {
        "name": "Elastic SIEM",
        "method": "Elasticsearch API, Beats",
        "format": "JSON, ECS",
        "features": ["Detection rules", "ML"]
    },
    "qradar": {
        "name": "IBM QRadar",
        "method": "Syslog, REST API",
        "format": "LEEF, CEF",
        "features": ["Offenses", "Rules"]
    },
    "sentinel": {
        "name": "Microsoft Sentinel",
        "method": "Log Analytics API",
        "format": "JSON",
        "features": ["KQL queries", "Playbooks"]
    },
    "chronicle": {
        "name": "Google Chronicle",
        "method": "Ingestion API",
        "format": "JSON, UDM",
        "features": ["Search", "Detection"]
    },
    "sumo_logic": {
        "name": "Sumo Logic",
        "method": "HTTP Source",
        "format": "JSON",
        "features": ["Cloud SIEM", "Search"]
    }
}

# =============================================================================
# HELPER FUNCTION TO GET ALL RESOURCES
# =============================================================================

def get_all_resources():
    """Return all resources as a single dictionary"""
    return {
        "threat_intel_feeds": len(THREAT_INTEL_FEEDS),
        "security_apis": len(SECURITY_APIS),
        "ml_datasets": len(ML_DATASETS),
        "yara_sources": len(YARA_SOURCES),
        "opensource_tools": len(OPENSOURCE_TOOLS),
        "potential_partners": len(POTENTIAL_PARTNERS),
        "email_integrations": len(EMAIL_INTEGRATIONS),
        "siem_integrations": len(SIEM_INTEGRATIONS),
        "total": (
            len(THREAT_INTEL_FEEDS) + len(SECURITY_APIS) + len(ML_DATASETS) +
            len(YARA_SOURCES) + len(OPENSOURCE_TOOLS) + len(POTENTIAL_PARTNERS) +
            len(EMAIL_INTEGRATIONS) + len(SIEM_INTEGRATIONS)
        )
    }
