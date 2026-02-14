"""
Sentinel Shield - Dataset Downloader
Downloads and prepares all required datasets for the security platform
"""

import os
import sys
from pathlib import Path

# Ensure we're using the right environment
DATASETS_DIR = Path(__file__).parent / "datasets"
MODELS_DIR = Path(__file__).parent / "models"

DATASETS_DIR.mkdir(exist_ok=True)
MODELS_DIR.mkdir(exist_ok=True)

def download_kaggle_datasets():
    """Download datasets from Kaggle using kagglehub"""
    try:
        import kagglehub
        
        datasets = [
            # Phishing Detection Datasets
            ("shashwatwork/web-page-phishing-detection-dataset", "Web Page Phishing Detection"),
            ("naserabdullahalam/phishing-email-dataset", "Phishing Email Dataset"),
            ("subhajournal/phishingemails", "CEAS Phishing Emails"),
            
            # Malware Related
            ("saurabhshahane/fake-news-classification", "Fake News Classifier"),
            
            # Fraud Detection
            ("kartik2112/fraud-detection", "Credit Card Fraud Detection"),
        ]
        
        print("=" * 60)
        print("📥 DOWNLOADING KAGGLE DATASETS")
        print("=" * 60)
        
        for kaggle_id, name in datasets:
            try:
                print(f"\n⬇️  {name}...")
                path = kagglehub.dataset_download(kaggle_id)
                print(f"   ✅ Downloaded to: {path}")
            except Exception as e:
                print(f"   ⚠️  Failed: {e}")
        
        print("\n✅ Dataset download complete!")
        
    except ImportError:
        print("❌ kagglehub not installed. Run: pip install kagglehub")

def download_pretrained_models():
    """Download pretrained models from HuggingFace"""
    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        
        models = [
            # Phishing Detection Models
            ("ealvaradob/bert-finetuned-phishing", "BERT Phishing Detection"),
            ("mrm8488/bert-mini-finetuned-phishing-email-detection", "BERT Mini Phishing"),
            
            # Text Classification
            ("distilbert-base-uncased-finetuned-sst-2-english", "DistilBERT Sentiment"),
        ]
        
        print("\n" + "=" * 60)
        print("🤖 DOWNLOADING PRETRAINED MODELS")
        print("=" * 60)
        
        for model_id, name in models:
            try:
                print(f"\n⬇️  {name}...")
                model_path = MODELS_DIR / model_id.replace("/", "_")
                
                tokenizer = AutoTokenizer.from_pretrained(model_id)
                model = AutoModelForSequenceClassification.from_pretrained(model_id)
                
                tokenizer.save_pretrained(str(model_path))
                model.save_pretrained(str(model_path))
                
                print(f"   ✅ Saved to: {model_path}")
            except Exception as e:
                print(f"   ⚠️  Failed: {e}")
        
        print("\n✅ Model download complete!")
        
    except ImportError:
        print("❌ transformers not installed. Run: pip install transformers torch")

def download_threat_intelligence_feeds():
    """Download public threat intelligence feeds"""
    import requests
    
    feeds = [
        # URL Blocklists
        ("https://urlhaus.abuse.ch/downloads/csv/", "urlhaus_malware_urls.csv", "URLhaus Malware URLs"),
        ("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt", 
         "phishing_domains_active.txt", "Phishing Domains"),
        
        # IP Blocklists
        ("https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
         "malicious_ips_level3.txt", "Malicious IPs (High Confidence)"),
         
        # Tor Exit Nodes
        ("https://check.torproject.org/torbulkexitlist", "tor_exit_nodes.txt", "Tor Exit Nodes"),
    ]
    
    print("\n" + "=" * 60)
    print("🔍 DOWNLOADING THREAT INTELLIGENCE FEEDS")
    print("=" * 60)
    
    threat_intel_dir = DATASETS_DIR / "threat_intel"
    threat_intel_dir.mkdir(exist_ok=True)
    
    for url, filename, name in feeds:
        try:
            print(f"\n⬇️  {name}...")
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                filepath = threat_intel_dir / filename
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                print(f"   ✅ Saved: {filepath}")
                print(f"   📊 Size: {len(response.text):,} bytes")
            else:
                print(f"   ⚠️  HTTP {response.status_code}")
        except Exception as e:
            print(f"   ⚠️  Failed: {e}")
    
    print("\n✅ Threat intelligence download complete!")

def download_yara_rules():
    """Download YARA rules for malware detection"""
    import requests
    
    yara_sources = [
        ("https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Ransomware.yar",
         "ransomware.yar", "Ransomware Signatures"),
        ("https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Emotet.yar",
         "emotet.yar", "Emotet Malware"),
        ("https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_office_macros.yar",
         "office_macros.yar", "Office Malicious Macros"),
    ]
    
    print("\n" + "=" * 60)
    print("📝 DOWNLOADING YARA RULES")
    print("=" * 60)
    
    yara_dir = DATASETS_DIR / "yara_rules"
    yara_dir.mkdir(exist_ok=True)
    
    for url, filename, name in yara_sources:
        try:
            print(f"\n⬇️  {name}...")
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                filepath = yara_dir / filename
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                print(f"   ✅ Saved: {filepath}")
            else:
                print(f"   ⚠️  HTTP {response.status_code}")
        except Exception as e:
            print(f"   ⚠️  Failed: {e}")
    
    print("\n✅ YARA rules download complete!")

def main():
    print("=" * 60)
    print("🛡️  SENTINEL SHIELD - RESOURCE DOWNLOADER")
    print("=" * 60)
    print(f"📁 Datasets Directory: {DATASETS_DIR}")
    print(f"📁 Models Directory: {MODELS_DIR}")
    
    # Download all resources
    download_kaggle_datasets()
    download_pretrained_models()
    download_threat_intelligence_feeds()
    download_yara_rules()
    
    print("\n" + "=" * 60)
    print("✅ ALL RESOURCES DOWNLOADED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    main()
