"""
Sentinel Shield - Enhanced Dataset Collection
Downloads and processes recent threat intelligence and training data
Focus on 2023-2024 datasets for current threat detection
"""

import os
import requests
import json
from pathlib import Path
from datetime import datetime
import hashlib

# Directories
BASE_DIR = Path(__file__).parent
DATASETS_DIR = BASE_DIR / "datasets"
THREAT_INTEL_DIR = DATASETS_DIR / "threat_intel"
ML_DATA_DIR = DATASETS_DIR / "ml_training"
YARA_DIR = DATASETS_DIR / "yara_rules"

# Create directories
for d in [DATASETS_DIR, THREAT_INTEL_DIR, ML_DATA_DIR, YARA_DIR]:
    d.mkdir(parents=True, exist_ok=True)


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


# =============================================================================
# THREAT INTELLIGENCE FEEDS (REAL-TIME, UPDATED DAILY)
# =============================================================================

THREAT_FEEDS = {
    # URLhaus - Malware URLs (Updated every 5 min)
    "urlhaus_online": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_online/",
        "filename": "urlhaus_online.csv",
        "description": "Currently online malware URLs",
        "update_frequency": "5 minutes"
    },
    
    # URLhaus - Full database
    "urlhaus_full": {
        "url": "https://urlhaus.abuse.ch/downloads/csv/",
        "filename": "urlhaus_full.csv",
        "description": "Full URLhaus database (2M+ entries)",
        "update_frequency": "hourly"
    },
    
    # Phishing.Database - Active phishing domains
    "phishing_domains": {
        "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        "filename": "phishing_domains_active.txt",
        "description": "Active phishing domains database",
        "update_frequency": "daily"
    },
    
    # Phishing URLs - NEW.txt (most recent)
    "phishing_urls_new": {
        "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW.txt",
        "filename": "phishing_urls_new.txt",
        "description": "Newly discovered phishing URLs",
        "update_frequency": "daily"
    },
    
    # OpenPhish - Community feed
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "filename": "openphish_feed.txt",
        "description": "OpenPhish community phishing URLs",
        "update_frequency": "12 hours"
    },
    
    # Feodo Tracker - Banking trojan C2
    "feodo_c2": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt",
        "filename": "feodo_c2_ips.txt",
        "description": "Feodo/Emotet/Dridex C2 IPs",
        "update_frequency": "hourly"
    },
    
    # SSLBL - Malicious SSL certificates
    "sslbl": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "filename": "ssl_blacklist.csv",
        "description": "Malicious SSL certificate IPs",
        "update_frequency": "hourly"
    },
    
    # IPsum - Multi-source IP reputation
    "ipsum_level3": {
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "filename": "ipsum_level3.txt",
        "description": "High-confidence malicious IPs (3+ sources)",
        "update_frequency": "daily"
    },
    
    # Tor Exit Nodes
    "tor_exits": {
        "url": "https://check.torproject.org/torbulkexitlist",
        "filename": "tor_exit_nodes.txt",
        "description": "Current Tor exit node list",
        "update_frequency": "hourly"
    },
    
    # Disposable email domains
    "disposable_emails": {
        "url": "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf",
        "filename": "disposable_emails.txt",
        "description": "Disposable/temporary email domains",
        "update_frequency": "weekly"
    },
    
    # Free email providers
    "free_email_providers": {
        "url": "https://gist.githubusercontent.com/tbrianjones/5992856/raw/87f527af7bdd21997a3c5c2e69e6be9a7c5b9ebc/free_email_provider_domains.txt",
        "filename": "free_email_providers.txt",
        "description": "Free email service provider domains",
        "update_frequency": "monthly"
    },
    
    # Newly registered domains (NRD) - High risk
    "newly_registered_domains": {
        "url": "https://raw.githubusercontent.com/xRuffKez/NRD/refs/heads/main/nrd-1w.txt",
        "filename": "newly_registered_domains_7d.txt",
        "description": "Domains registered in last 7 days",
        "update_frequency": "daily"
    },
    
    # Ransomware tracker
    "ransomware_urls": {
        "url": "https://raw.githubusercontent.com/codeswhite/ransomware-tracker/master/feed.txt",
        "filename": "ransomware_urls.txt",
        "description": "Known ransomware distribution URLs",
        "update_frequency": "daily"
    },
    
    # MalwareBazaar - Recent samples (SHA256)
    "malware_hashes": {
        "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        "filename": "malware_sha256_recent.txt",
        "description": "Recent malware sample hashes",
        "update_frequency": "hourly"
    },
    
    # ThreatFox - IOC database
    "threatfox_urls": {
        "url": "https://threatfox.abuse.ch/export/csv/urls/recent/",
        "filename": "threatfox_urls.csv",
        "description": "ThreatFox URL IOCs",
        "update_frequency": "hourly"
    }
}


def download_threat_feed(feed_name: str, feed_info: dict):
    """Download a single threat feed"""
    
    filepath = THREAT_INTEL_DIR / feed_info['filename']
    
    try:
        log(f"⬇️  Downloading {feed_name}...")
        
        response = requests.get(
            feed_info['url'],
            timeout=60,
            headers={'User-Agent': 'SentinelShield/1.0'}
        )
        
        if response.status_code == 200:
            with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(response.text)
            
            # Count lines
            lines = len(response.text.strip().split('\n'))
            size_kb = len(response.content) / 1024
            
            log(f"   ✅ {feed_name}: {lines:,} entries ({size_kb:.1f} KB)")
            return True
        else:
            log(f"   ⚠️  {feed_name}: HTTP {response.status_code}")
            return False
            
    except Exception as e:
        log(f"   ❌ {feed_name}: {str(e)[:50]}")
        return False


# =============================================================================
# YARA RULES (MALWARE DETECTION)
# =============================================================================

YARA_RULESETS = {
    "yara_rules_core": {
        "url": "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Ransomware.yar",
        "filename": "ransomware.yar",
        "description": "Ransomware detection rules"
    },
    "yara_maldocs": {
        "url": "https://raw.githubusercontent.com/Yara-Rules/rules/master/maldocs/Maldoc_PDF.yar",
        "filename": "maldocs_pdf.yar",
        "description": "Malicious PDF detection"
    },
    "yara_webshells": {
        "url": "https://raw.githubusercontent.com/Yara-Rules/rules/master/webshells/webshell_generic.yar",
        "filename": "webshells.yar",
        "description": "Webshell detection rules"
    },
    "yara_exploits": {
        "url": "https://raw.githubusercontent.com/Yara-Rules/rules/master/exploits/exploit_generic.yar",
        "filename": "exploits.yar",
        "description": "Exploit detection rules"
    },
    "thor_phishing": {
        "url": "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_phishing.yar",
        "filename": "phishing.yar",
        "description": "Phishing document detection"
    },
    "thor_office_macros": {
        "url": "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_office_macros.yar",
        "filename": "office_macros.yar",
        "description": "Malicious Office macro detection"
    }
}


def download_yara_rules():
    """Download YARA rulesets"""
    
    log("\n📜 Downloading YARA rules...")
    
    for name, info in YARA_RULESETS.items():
        filepath = YARA_DIR / info['filename']
        
        try:
            response = requests.get(info['url'], timeout=30)
            if response.status_code == 200:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                log(f"   ✅ {info['filename']}")
            else:
                log(f"   ⚠️  {info['filename']}: HTTP {response.status_code}")
        except Exception as e:
            log(f"   ❌ {info['filename']}: {str(e)[:50]}")


# =============================================================================
# ML TRAINING DATASETS (KAGGLE)
# =============================================================================

KAGGLE_DATASETS = {
    "phishing_emails": {
        "dataset": "venky73/spam-mails-dataset",
        "description": "Spam and phishing email corpus"
    },
    "phishing_urls": {
        "dataset": "sid321axn/malicious-urls-dataset",
        "description": "Malicious URL dataset with labels"
    },
    "fraud_emails": {
        "dataset": "rtatman/fraudulent-email-corpus",
        "description": "Nigerian prince and fraud emails"
    },
    "emails_nlp": {
        "dataset": "veleon/ham-and-spam-dataset",
        "description": "Ham/Spam with NLP features"
    },
    "phishing_2024": {
        "dataset": "akashrastogi/phishing-dataset-2024",
        "description": "Latest 2024 phishing URLs"
    }
}


def download_kaggle_datasets():
    """Download Kaggle datasets using kagglehub"""
    
    log("\n📊 Downloading Kaggle datasets...")
    
    try:
        import kagglehub
        
        for name, info in KAGGLE_DATASETS.items():
            try:
                log(f"   ⬇️  {info['dataset']}...")
                path = kagglehub.dataset_download(info['dataset'])
                log(f"      ✅ Downloaded to: {path}")
            except Exception as e:
                log(f"      ⚠️  {name}: {str(e)[:60]}")
                
    except ImportError:
        log("   ⚠️  kagglehub not installed. Run: pip install kagglehub")


# =============================================================================
# BRAND/COMPANY DATA (For impersonation detection)
# =============================================================================

def create_brand_database():
    """Create database of brand patterns for impersonation detection"""
    
    log("\n🏢 Creating brand database...")
    
    brands = {
        "microsoft": {
            "domains": ["microsoft.com", "office.com", "live.com", "outlook.com", "azure.com", "msn.com"],
            "keywords": ["microsoft", "office365", "outlook", "azure", "windows"],
            "homoglyphs": ["rnicrosoft", "microsft", "rnlcrosoft", "n1crosoft"]
        },
        "google": {
            "domains": ["google.com", "gmail.com", "youtube.com", "drive.google.com"],
            "keywords": ["google", "gmail", "youtube", "drive"],
            "homoglyphs": ["g00gle", "googIe", "goog1e", "gooogle"]
        },
        "amazon": {
            "domains": ["amazon.com", "aws.amazon.com", "amzn.to"],
            "keywords": ["amazon", "prime", "aws"],
            "homoglyphs": ["amaz0n", "arnazon", "amаzon"]
        },
        "apple": {
            "domains": ["apple.com", "icloud.com", "appleid.apple.com"],
            "keywords": ["apple", "icloud", "appleid", "itunes"],
            "homoglyphs": ["аpple", "app1e", "appIe"]
        },
        "paypal": {
            "domains": ["paypal.com", "paypal.me"],
            "keywords": ["paypal", "payment"],
            "homoglyphs": ["paypa1", "paypаl", "pаypal", "paypaI"]
        },
        "netflix": {
            "domains": ["netflix.com"],
            "keywords": ["netflix", "streaming"],
            "homoglyphs": ["netf1ix", "netfIix", "nеtflix"]
        },
        "facebook": {
            "domains": ["facebook.com", "fb.com", "meta.com"],
            "keywords": ["facebook", "meta", "instagram"],
            "homoglyphs": ["faceb00k", "fаcebook", "facebooк"]
        },
        "linkedin": {
            "domains": ["linkedin.com"],
            "keywords": ["linkedin", "professional"],
            "homoglyphs": ["linkedln", "1inkedin", "linkеdin"]
        },
        "chase": {
            "domains": ["chase.com", "jpmorganchase.com"],
            "keywords": ["chase", "jpmorgan", "banking"],
            "homoglyphs": ["chаse", "сhase", "chasе"]
        },
        "bankofamerica": {
            "domains": ["bankofamerica.com", "bofa.com"],
            "keywords": ["bank of america", "bofa", "banking"],
            "homoglyphs": ["bankofаmerica", "bаnkofamerica"]
        },
        "wellsfargo": {
            "domains": ["wellsfargo.com"],
            "keywords": ["wells fargo", "banking"],
            "homoglyphs": ["wellsfarg0", "weIlsfargo"]
        },
        "docusign": {
            "domains": ["docusign.com", "docusign.net"],
            "keywords": ["docusign", "signature", "document"],
            "homoglyphs": ["d0cusign", "docuslgn"]
        },
        "dropbox": {
            "domains": ["dropbox.com"],
            "keywords": ["dropbox", "file sharing"],
            "homoglyphs": ["dr0pbox", "dropb0x"]
        },
        "ups": {
            "domains": ["ups.com"],
            "keywords": ["ups", "delivery", "shipping"],
            "homoglyphs": ["uрs"]
        },
        "fedex": {
            "domains": ["fedex.com"],
            "keywords": ["fedex", "delivery", "shipping"],
            "homoglyphs": ["fеdex", "fedеx"]
        },
        "dhl": {
            "domains": ["dhl.com"],
            "keywords": ["dhl", "delivery", "express"],
            "homoglyphs": ["dhI", "dh1"]
        }
    }
    
    # Save to file
    filepath = ML_DATA_DIR / "brand_database.json"
    with open(filepath, 'w') as f:
        json.dump(brands, f, indent=2)
    
    log(f"   ✅ Brand database: {len(brands)} brands saved")
    return brands


# =============================================================================
# HOMOGLYPH DATABASE
# =============================================================================

def create_homoglyph_database():
    """Create comprehensive homoglyph mapping database"""
    
    log("\n🔤 Creating homoglyph database...")
    
    homoglyphs = {
        # ASCII lookalikes
        "ascii_pairs": {
            "rn": "m",
            "vv": "w",
            "cl": "d",
            "1": "l",
            "0": "o",
            "5": "s",
            "8": "b"
        },
        
        # Cyrillic lookalikes (very common in phishing)
        "cyrillic": {
            "\u0430": "a",  # Cyrillic а
            "\u0435": "e",  # Cyrillic е
            "\u043e": "o",  # Cyrillic о
            "\u0440": "p",  # Cyrillic р
            "\u0441": "c",  # Cyrillic с
            "\u0443": "y",  # Cyrillic у
            "\u0445": "x",  # Cyrillic х
            "\u0456": "i",  # Cyrillic і
            "\u0458": "j",  # Cyrillic ј
        },
        
        # Greek lookalikes
        "greek": {
            "\u03b1": "a",  # Greek α
            "\u03b5": "e",  # Greek ε  
            "\u03bf": "o",  # Greek ο
            "\u03c1": "p",  # Greek ρ
        },
        
        # Unicode math/special
        "unicode": {
            "\uff21": "A",  # Fullwidth A
            "\uff41": "a",  # Fullwidth a
            "\u0251": "a",  # Latin small alpha
        },
        
        # Common substitutions
        "leet_speak": {
            "@": "a",
            "4": "a",
            "3": "e",
            "1": "i",
            "!": "i",
            "0": "o",
            "$": "s",
            "7": "t",
            "+": "t"
        }
    }
    
    filepath = ML_DATA_DIR / "homoglyph_database.json"
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(homoglyphs, f, indent=2, ensure_ascii=False)
    
    total = sum(len(v) for v in homoglyphs.values())
    log(f"   ✅ Homoglyph database: {total} mappings saved")
    return homoglyphs


# =============================================================================
# SUSPICIOUS TLD DATABASE
# =============================================================================

def create_tld_risk_database():
    """Create TLD risk score database"""
    
    log("\n🌐 Creating TLD risk database...")
    
    tld_risk = {
        # Very high risk (commonly abused, almost never legitimate)
        "very_high": {
            "tlds": [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".icu", ".buzz", 
                     ".work", ".click", ".link", ".best", ".rest", ".host"],
            "score": 30,
            "reason": "Free/cheap TLDs heavily abused in phishing"
        },
        
        # High risk (commonly abused but some legitimate use)
        "high": {
            "tlds": [".info", ".biz", ".online", ".site", ".website", ".space", 
                     ".fun", ".download", ".win", ".review", ".party", ".loan"],
            "score": 20,
            "reason": "High phishing/spam prevalence"
        },
        
        # Medium risk (some abuse)
        "medium": {
            "tlds": [".pw", ".cc", ".ws", ".us", ".mobi", ".in", ".ru"],
            "score": 10,
            "reason": "Moderate abuse seen"
        },
        
        # Low risk (established, well-regulated)
        "low": {
            "tlds": [".com", ".org", ".net", ".edu", ".gov", ".co.uk", ".de", ".fr"],
            "score": 0,
            "reason": "Established TLDs with good reputation"
        }
    }
    
    filepath = ML_DATA_DIR / "tld_risk_database.json"
    with open(filepath, 'w') as f:
        json.dump(tld_risk, f, indent=2)
    
    total_tlds = sum(len(v["tlds"]) for v in tld_risk.values())
    log(f"   ✅ TLD risk database: {total_tlds} TLDs categorized")
    return tld_risk


# =============================================================================
# URGENCY KEYWORDS DATABASE
# =============================================================================

def create_urgency_database():
    """Create urgency keyword database with weights"""
    
    log("\n⚡ Creating urgency keyword database...")
    
    urgency = {
        "critical": {
            "keywords": ["urgent", "immediate action required", "account suspended",
                        "verify now", "confirm your identity", "expires today",
                        "last warning", "final notice", "unauthorized access",
                        "security alert", "your account has been compromised"],
            "score": 25
        },
        "high": {
            "keywords": ["act now", "limited time", "confirm within 24 hours",
                        "important update", "verify your account", "suspicious activity",
                        "unusual sign-in", "password expiring", "payment failed"],
            "score": 15
        },
        "medium": {
            "keywords": ["please respond", "action needed", "update required",
                        "review your account", "time sensitive", "respond today"],
            "score": 10
        },
        "low": {
            "keywords": ["reminder", "follow up", "just checking", "fyi"],
            "score": 5
        }
    }
    
    filepath = ML_DATA_DIR / "urgency_database.json"
    with open(filepath, 'w') as f:
        json.dump(urgency, f, indent=2)
    
    total = sum(len(v["keywords"]) for v in urgency.values())
    log(f"   ✅ Urgency database: {total} keywords categorized")
    return urgency


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("=" * 70)
    print("🛡️  SENTINEL SHIELD - ENHANCED DATASET COLLECTION")
    print("=" * 70)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Download threat intelligence feeds
    log("📡 Downloading threat intelligence feeds...")
    success_count = 0
    for name, info in THREAT_FEEDS.items():
        if download_threat_feed(name, info):
            success_count += 1
    log(f"\n   📊 Threat feeds: {success_count}/{len(THREAT_FEEDS)} successful")
    
    # Download YARA rules
    download_yara_rules()
    
    # Create reference databases
    create_brand_database()
    create_homoglyph_database()
    create_tld_risk_database()
    create_urgency_database()
    
    # Try Kaggle datasets (optional, requires kagglehub)
    try:
        download_kaggle_datasets()
    except Exception as e:
        log(f"   ⚠️  Kaggle download skipped: {e}")
    
    # Summary
    print()
    print("=" * 70)
    print("✅ DATASET COLLECTION COMPLETE")
    print("=" * 70)
    
    # Count files
    threat_files = list(THREAT_INTEL_DIR.glob("*"))
    yara_files = list(YARA_DIR.glob("*.yar"))
    ml_files = list(ML_DATA_DIR.glob("*"))
    
    print(f"\n📁 Files downloaded:")
    print(f"   Threat Intel:  {len(threat_files)} files in {THREAT_INTEL_DIR}")
    print(f"   YARA Rules:    {len(yara_files)} files in {YARA_DIR}")
    print(f"   ML Data:       {len(ml_files)} files in {ML_DATA_DIR}")
    
    # Total size
    total_size = sum(f.stat().st_size for f in THREAT_INTEL_DIR.glob("*") if f.is_file())
    total_size += sum(f.stat().st_size for f in YARA_DIR.glob("*") if f.is_file())
    total_size += sum(f.stat().st_size for f in ML_DATA_DIR.glob("*") if f.is_file())
    
    print(f"\n   Total size: {total_size / 1024 / 1024:.1f} MB")
    print()


if __name__ == "__main__":
    main()
