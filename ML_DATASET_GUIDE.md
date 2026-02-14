# 📊 Dataset Setup & ML Model Development Guide

## 🎯 Kaggle Datasets Integration

### Step 1: Install Kaggle API
```bash
pip install kagglehub pandas numpy scikit-learn matplotlib seaborn
pip install whois python-whois tldextract
```

### Step 2: Download & Prepare Datasets

```python
import kagglehub
import pandas as pd
import os

# Dataset 1: Web Page Phishing Detection
path1 = kagglehub.dataset_download("shashwatwork/web-page-phishing-detection-dataset")
print("Web Page Dataset:", path1)

# Dataset 2: Phishing Email Dataset
path2 = kagglehub.dataset_download("naserabdullahalam/phishing-email-dataset")
print("Email Dataset:", path2)
```

### Step 3: Data Loading & Preparation Script

Create `ml-service/data_preparation.py`:

```python
import pandas as pd
import numpy as np
from pathlib import Path
import json
import re
from typing import Dict, List, Tuple

class PhishingDatasetProcessor:
    """Process and combine multiple phishing datasets"""
    
    def __init__(self, data_dir: str = './datasets'):
        self.data_dir = Path(data_dir)
        self.combined_data = None
        
    def load_web_dataset(self, path: str) -> pd.DataFrame:
        """Load web page phishing dataset"""
        df = pd.read_csv(path)
        print(f"Web Dataset Shape: {df.shape}")
        print(f"Columns: {df.columns.tolist()}")
        return df
    
    def load_email_dataset(self, path: str) -> pd.DataFrame:
        """Load email phishing dataset"""
        df = pd.read_csv(path)
        print(f"Email Dataset Shape: {df.shape}")
        print(f"Columns: {df.columns.tolist()}")
        return df
    
    def extract_email_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract features from email text"""
        features = []
        
        for idx, row in df.iterrows():
            text = str(row.get('email_text', '')) + ' ' + str(row.get('subject', ''))
            
            feature = {
                'text': text,
                'has_urgency': self._check_urgency(text),
                'has_sensitive_words': self._check_sensitive(text),
                'url_count': self._count_urls(text),
                'suspicious_domains': self._check_suspicious_domains(text),
                'has_ip_address': self._has_ip_address(text),
                'has_attachments': self._check_attachments(text),
                'char_substitution': self._check_char_substitution(text),
                'formality_score': self._calculate_formality(text),
                'label': row.get('label', row.get('is_phishing', 0))
            }
            features.append(feature)
        
        return pd.DataFrame(features)
    
    def _check_urgency(self, text: str) -> int:
        urgent_keywords = [
            'urgent', 'immediate', 'act now', 'expires today',
            'suspended', 'locked', 'verify now', 'last chance',
            'limited time', 'alert', 'warning', 'final notice'
        ]
        return sum(1 for keyword in urgent_keywords if keyword in text.lower())
    
    def _check_sensitive(self, text: str) -> int:
        sensitive_words = [
            'password', 'ssn', 'social security', 'credit card',
            'bank account', 'pin', 'cvv', 'routing number'
        ]
        return sum(1 for word in sensitive_words if word in text.lower())
    
    def _count_urls(self, text: str) -> int:
        url_pattern = r'https?://[^\s]+'
        return len(re.findall(url_pattern, text))
    
    def _check_suspicious_domains(self, text: str) -> int:
        url_pattern = r'https?://[^\s]+'
        urls = re.findall(url_pattern, text)
        suspicious_patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address
            r'bit\.ly|tinyurl|goo\.gl',  # URL shorteners
            r'-secure|-verify|-update|-confirm'  # Suspicious keywords in domain
        ]
        count = 0
        for url in urls:
            for pattern in suspicious_patterns:
                if re.search(pattern, url):
                    count += 1
        return count
    
    def _has_ip_address(self, text: str) -> int:
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        return 1 if re.search(ip_pattern, text) else 0
    
    def _check_attachments(self, text: str) -> int:
        dangerous_exts = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.zip']
        return sum(1 for ext in dangerous_exts if ext in text.lower())
    
    def _check_char_substitution(self, text: str) -> int:
        """Check for character substitution (rn vs m, etc)"""
        patterns = ['rn', 'vv', 'cl', 'l1', '0O']
        score = 0
        for pattern in patterns:
            # Check if pattern appears in suspicious context
            if pattern in text and re.search(r'\w*' + pattern + r'\w*', text):
                score += 1
        return score
    
    def _calculate_formality(self, text: str) -> float:
        """Calculate email formality score (0-100)"""
        score = 100.0
        text_lower = text.lower()
        
        # Deduct for informal language
        informal_patterns = [
            (r'\b(ur|u r)\b', -10),
            (r'!!!+', -5),
            (r'\?\?\?+', -5),
            (r'[A-Z]{10,}', -10),
            (r'\b(gonna|wanna|gotta)\b', -5)
        ]
        
        for pattern, penalty in informal_patterns:
            if re.search(pattern, text):
                score += penalty
        
        # Check for professional structure
        if re.search(r'\b(dear|hello|hi)\b', text_lower):
            score += 5
        if re.search(r'\b(regards|sincerely|best)\b', text_lower):
            score += 5
            
        return max(0, min(100, score))
    
    def save_processed_data(self, df: pd.DataFrame, filename: str):
        """Save processed dataset"""
        output_path = self.data_dir / filename
        df.to_csv(output_path, index=False)
        print(f"Saved processed data to: {output_path}")
        return output_path
    
    def create_training_data(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Create train/test split"""
        from sklearn.model_selection import train_test_split
        
        if self.combined_data is None:
            raise ValueError("No data loaded. Run load_and_combine() first.")
        
        X = self.combined_data.drop('label', axis=1)
        y = self.combined_data['label']
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"Training set: {X_train.shape[0]} samples")
        print(f"Test set: {X_test.shape[0]} samples")
        print(f"Phishing ratio: {y.mean():.2%}")
        
        return (X_train, y_train), (X_test, y_test)

# Usage example
if __name__ == '__main__':
    processor = PhishingDatasetProcessor()
    
    # Load datasets
    web_df = processor.load_web_dataset('path/to/web/dataset.csv')
    email_df = processor.load_email_dataset('path/to/email/dataset.csv')
    
    # Process email data
    email_features = processor.extract_email_features(email_df)
    processor.combined_data = email_features
    
    # Save processed data
    processor.save_processed_data(email_features, 'processed_phishing_data.csv')
    
    # Create training data
    (X_train, y_train), (X_test, y_test) = processor.create_training_data()
```

---

## 🤖 Enhanced ML Model with Pre-trained Options

### Option 1: Train Custom Model

Create `ml-service/train_model.py`:

```python
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import json

class PhishingDetector:
    """Advanced phishing detection model"""
    
    def __init__(self):
        self.text_vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3),
            min_df=2
        )
        self.feature_scaler = StandardScaler()
        self.model = GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.1,
            max_depth=5,
            random_state=42
        )
        
    def prepare_features(self, df: pd.DataFrame, fit: bool = False):
        """Prepare features for training/prediction"""
        # Text features (TF-IDF)
        text_features = self.text_vectorizer.fit_transform(df['text']) if fit \
                       else self.text_vectorizer.transform(df['text'])
        
        # Numerical features
        numerical_cols = [
            'has_urgency', 'has_sensitive_words', 'url_count',
            'suspicious_domains', 'has_ip_address', 'has_attachments',
            'char_substitution', 'formality_score'
        ]
        numerical_features = df[numerical_cols].values
        
        if fit:
            numerical_features = self.feature_scaler.fit_transform(numerical_features)
        else:
            numerical_features = self.feature_scaler.transform(numerical_features)
        
        # Combine features
        import scipy.sparse as sp
        combined = sp.hstack([text_features, numerical_features])
        
        return combined
    
    def train(self, X_train, y_train, X_test, y_test):
        """Train the model"""
        print("Preparing features...")
        X_train_features = self.prepare_features(X_train, fit=True)
        X_test_features = self.prepare_features(X_test, fit=False)
        
        print("Training model...")
        self.model.fit(X_train_features, y_train)
        
        # Evaluate
        train_score = self.model.score(X_train_features, y_train)
        test_score = self.model.score(X_test_features, y_test)
        
        print(f"Training accuracy: {train_score:.4f}")
        print(f"Test accuracy: {test_score:.4f}")
        
        # Detailed evaluation
        y_pred = self.model.predict(X_test_features)
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        return test_score
    
    def predict(self, text: str, features: dict) -> dict:
        """Predict if email is phishing"""
        # Create DataFrame with single sample
        data = {
            'text': [text],
            **{k: [v] for k, v in features.items()}
        }
        df = pd.DataFrame(data)
        
        # Prepare features
        X = self.prepare_features(df, fit=False)
        
        # Predict
        prediction = self.model.predict(X)[0]
        probability = self.model.predict_proba(X)[0]
        
        return {
            'is_phishing': bool(prediction),
            'confidence': float(probability[1]),
            'threat_score': int(probability[1] * 100)
        }
    
    def save(self, path: str = 'models/phishing_detector.joblib'):
        """Save model and preprocessors"""
        joblib.dump({
            'model': self.model,
            'text_vectorizer': self.text_vectorizer,
            'feature_scaler': self.feature_scaler
        }, path)
        print(f"Model saved to: {path}")
    
    def load(self, path: str = 'models/phishing_detector.joblib'):
        """Load model and preprocessors"""
        data = joblib.load(path)
        self.model = data['model']
        self.text_vectorizer = data['text_vectorizer']
        self.feature_scaler = data['feature_scaler']
        print(f"Model loaded from: {path}")
```

### Option 2: Use Pre-trained Models

```python
# Using Hugging Face transformers for advanced detection
pip install transformers torch

# Pre-trained phishing detection models available:
# 1. ealvaradob/bert-finetuned-phishing
# 2. mrm8488/bert-small-finetuned-sms-phishing-detection

from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

class TransformerPhishingDetector:
    def __init__(self, model_name="ealvaradob/bert-finetuned-phishing"):
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_name)
        
    def predict(self, text: str) -> dict:
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        outputs = self.model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1)
        
        return {
            'is_phishing': bool(torch.argmax(probs)),
            'confidence': float(probs[0][1]),
            'threat_score': int(probs[0][1] * 100)
        }
```

---

## 🔍 Research-Enhanced Features

### 1. Advanced Link Analysis

Create `ml-service/services/link_analyzer.py`:

```python
import re
import whois
import tldextract
from datetime import datetime, timedelta
from typing import Dict, List
import requests
from urllib.parse import urlparse

class AdvancedLinkAnalyzer:
    """Research-backed link analysis with domain intelligence"""
    
    def __init__(self):
        self.known_brands = self._load_brand_list()
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz']
        
    def analyze_url(self, url: str) -> Dict:
        """Comprehensive URL analysis"""
        analysis = {
            'url': url,
            'threat_score': 0,
            'indicators': []
        }
        
        # 1. Domain extraction
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        subdomain = extracted.subdomain
        
        # 2. Domain age check
        age_result = self._check_domain_age(domain)
        analysis['domain_age_days'] = age_result['age_days']
        if age_result['is_suspicious']:
            analysis['threat_score'] += 30
            analysis['indicators'].append({
                'type': 'new_domain',
                'severity': 'high',
                'description': f"Domain registered {age_result['age_days']} days ago"
            })
        
        # 3. Subdomain analysis
        subdomain_risk = self._analyze_subdomain(subdomain, domain)
        if subdomain_risk['is_suspicious']:
            analysis['threat_score'] += subdomain_risk['score']
            analysis['indicators'].append(subdomain_risk['indicator'])
        
        # 4. Brand impersonation check
        brand_check = self._check_brand_impersonation(url, domain, subdomain)
        if brand_check['is_impersonation']:
            analysis['threat_score'] += 40
            analysis['indicators'].append(brand_check['indicator'])
        
        # 5. Redirect behavior
        redirect_check = self._check_redirects(url)
        if redirect_check['is_suspicious']:
            analysis['threat_score'] += redirect_check['score']
            analysis['indicators'].extend(redirect_check['indicators'])
        
        # 6. URL structure analysis
        structure_check = self._analyze_url_structure(url)
        analysis['threat_score'] += structure_check['score']
        analysis['indicators'].extend(structure_check['indicators'])
        
        # 7. Ephemeral domain detection
        if self._is_ephemeral_domain(extracted.suffix):
            analysis['threat_score'] += 25
            analysis['indicators'].append({
                'type': 'ephemeral_domain',
                'severity': 'medium',
                'description': f"Uses disposable TLD: {extracted.suffix}"
            })
        
        analysis['threat_score'] = min(100, analysis['threat_score'])
        analysis['threat_level'] = self._get_threat_level(analysis['threat_score'])
        
        return analysis
    
    def _check_domain_age(self, domain: str) -> Dict:
        """Check domain registration age"""
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                
                # Domains < 30 days are suspicious
                is_suspicious = age_days < 30
                
                return {
                    'age_days': age_days,
                    'is_suspicious': is_suspicious,
                    'creation_date': creation_date.isoformat()
                }
        except Exception as e:
            print(f"WHOIS lookup failed for {domain}: {e}")
        
        return {'age_days': None, 'is_suspicious': True}
    
    def _analyze_subdomain(self, subdomain: str, domain: str) -> Dict:
        """Analyze subdomain for suspicious patterns"""
        if not subdomain:
            return {'is_suspicious': False, 'score': 0}
        
        # Multiple subdomains are suspicious
        subdomain_parts = subdomain.split('.')
        if len(subdomain_parts) > 2:
            return {
                'is_suspicious': True,
                'score': 15,
                'indicator': {
                    'type': 'excessive_subdomains',
                    'severity': 'medium',
                    'description': f"Multiple subdomain levels: {subdomain}"
                }
            }
        
        # Subdomain contains brand name but domain doesn't
        for brand in self.known_brands:
            if brand in subdomain.lower() and brand not in domain.lower():
                return {
                    'is_suspicious': True,
                    'score': 35,
                    'indicator': {
                        'type': 'brand_in_subdomain',
                        'severity': 'high',
                        'description': f"Brand '{brand}' in subdomain, not main domain"
                    }
                }
        
        # Suspicious keywords in subdomain
        suspicious_keywords = ['secure', 'login', 'verify', 'account', 'update', 'confirm']
        for keyword in suspicious_keywords:
            if keyword in subdomain.lower():
                return {
                    'is_suspicious': True,
                    'score': 20,
                    'indicator': {
                        'type': 'suspicious_subdomain',
                        'severity': 'medium',
                        'description': f"Suspicious keyword '{keyword}' in subdomain"
                    }
                }
        
        return {'is_suspicious': False, 'score': 0}
    
    def _check_brand_impersonation(self, url: str, domain: str, subdomain: str) -> Dict:
        """Detect brand impersonation attempts"""
        url_lower = url.lower()
        domain_lower = domain.lower()
        full_domain = f"{subdomain}.{domain}".lower() if subdomain else domain_lower
        
        for brand in self.known_brands:
            # Brand in URL but not official domain
            if brand in url_lower:
                # Check if it's the actual brand domain
                official_domains = [f"{brand}.com", f"{brand}.net", f"{brand}.org"]
                
                if not any(official in full_domain for official in official_domains):
                    # Check for typosquatting
                    similarity = self._calculate_similarity(brand, domain_lower)
                    
                    if similarity > 0.7:  # Suspicious similarity
                        return {
                            'is_impersonation': True,
                            'indicator': {
                                'type': 'brand_impersonation',
                                'severity': 'critical',
                                'description': f"Possible {brand} impersonation (similarity: {similarity:.0%})"
                            }
                        }
        
        return {'is_impersonation': False}
    
    def _check_redirects(self, url: str) -> Dict:
        """Check for suspicious redirect chains"""
        indicators = []
        score = 0
        
        try:
            response = requests.get(url, allow_redirects=True, timeout=5)
            
            # Check redirect chain
            if len(response.history) > 0:
                redirect_count = len(response.history)
                
                if redirect_count > 2:
                    score += 20
                    indicators.append({
                        'type': 'multiple_redirects',
                        'severity': 'medium',
                        'description': f"Multiple redirects detected ({redirect_count})"
                    })
                
                # Check if redirects to different domain
                original_domain = urlparse(url).netloc
                final_domain = urlparse(response.url).netloc
                
                if original_domain != final_domain:
                    score += 25
                    indicators.append({
                        'type': 'domain_change_redirect',
                        'severity': 'high',
                        'description': f"Redirects to different domain: {final_domain}"
                    })
        
        except Exception as e:
            # URL not reachable might be suspicious
            score += 10
            indicators.append({
                'type': 'unreachable_url',
                'severity': 'medium',
                'description': f"URL not accessible: {str(e)}"
            })
        
        return {
            'is_suspicious': score > 0,
            'score': score,
            'indicators': indicators
        }
    
    def _analyze_url_structure(self, url: str) -> Dict:
        """Analyze URL structure for anomalies"""
        indicators = []
        score = 0
        
        # IP address in URL
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            score += 40
            indicators.append({
                'type': 'ip_address_url',
                'severity': 'critical',
                'description': 'URL uses IP address instead of domain'
            })
        
        # Excessive length
        if len(url) > 100:
            score += 15
            indicators.append({
                'type': 'long_url',
                'severity': 'low',
                'description': f'Unusually long URL ({len(url)} characters)'
            })
        
        # Excessive special characters
        special_chars = sum(1 for c in url if c in '@-_.')
        if special_chars > 5:
            score += 10
            indicators.append({
                'type': 'excessive_special_chars',
                'severity': 'low',
                'description': f'Many special characters ({special_chars})'
            })
        
        # @ symbol in URL (used to hide real domain)
        if '@' in url:
            score += 35
            indicators.append({
                'type': 'at_symbol',
                'severity': 'high',
                'description': 'Contains @ symbol (may hide real destination)'
            })
        
        return {'score': score, 'indicators': indicators}
    
    def _is_ephemeral_domain(self, tld: str) -> bool:
        """Check if domain uses ephemeral/disposable TLD"""
        return f".{tld}" in self.suspicious_tlds
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate string similarity (Levenshtein distance)"""
        from difflib import SequenceMatcher
        return SequenceMatcher(None, str1, str2).ratio()
    
    def _get_threat_level(self, score: int) -> str:
        """Determine threat level from score"""
        if score < 30:
            return 'safe'
        elif score < 60:
            return 'suspicious'
        elif score < 85:
            return 'dangerous'
        return 'critical'
    
    def _load_brand_list(self) -> List[str]:
        """Load list of known brands to protect"""
        return [
            'paypal', 'amazon', 'microsoft', 'google', 'apple',
            'facebook', 'netflix', 'ebay', 'bank', 'wells',
            'chase', 'citibank', 'irs', 'dhl', 'fedex',
            'ups', 'usps', 'instagram', 'twitter', 'linkedin'
        ]
```

---

## 🚨 Automated Response & Containment

Create `backend/src/services/automated-response.service.js`:

(Continue to next file...)
