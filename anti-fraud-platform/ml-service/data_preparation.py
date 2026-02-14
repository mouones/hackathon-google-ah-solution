import pandas as pd
import numpy as np
from pathlib import Path
import re
from typing import Tuple
from sklearn.model_selection import train_test_split

class PhishingDatasetProcessor:
    """Process and combine multiple phishing datasets"""
    
    def __init__(self, datasets_dir: str = None):
        self.datasets_dir = Path(datasets_dir) if datasets_dir else None
        self.combined_data = None
        
    def load_datasets(self, web_path: str, email_path: str) -> pd.DataFrame:
        """Load and combine both datasets"""
        print("Loading datasets...")
        print("=" * 60)
        
        # Load email dataset (primary)
        email_df = pd.read_csv(email_path)
        print(f"✓ Email dataset loaded: {email_df.shape}")
        print(f"  Columns: {email_df.columns.tolist()[:5]}...")
        
        # Process email data
        email_features = self.extract_email_features(email_df)
        
        self.combined_data = email_features
        print(f"\n✓ Combined dataset shape: {self.combined_data.shape}")
        print(f"  Phishing ratio: {self.combined_data['label'].mean():.2%}")
        
        return self.combined_data
    
    def extract_email_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract features from email text"""
        print("\nExtracting features from emails...")
        features = []
        
        for idx, row in df.iterrows():
            # Combine available text fields
            text_parts = []
            for col in ['text_combined', 'Email Text', 'text', 'email_text', 'body', 'subject', 'Subject']:
                if col in row and pd.notna(row[col]):
                    text_parts.append(str(row[col]))
            
            text = ' '.join(text_parts) if text_parts else ''
            
            # Extract label
            label = 0
            for label_col in ['Email Type', 'label', 'is_phishing', 'class']:
                if label_col in row:
                    val = row[label_col]
                    if val in ['Phishing Email', 'phishing', 'spam', 1, '1']:
                        label = 1
                    break
            
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
                'label': label
            }
            features.append(feature)
            
            if (idx + 1) % 1000 == 0:
                print(f"  Processed {idx + 1} emails...")
        
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
    
    def save_processed_data(self, filename: str = 'processed_phishing_data.csv'):
        """Save processed dataset"""
        if self.combined_data is None:
            raise ValueError("No data to save. Run load_datasets() first.")
        
        output_path = Path(filename)
        self.combined_data.to_csv(output_path, index=False)
        print(f"\n✓ Saved processed data to: {output_path}")
        return output_path
    
    def create_training_data(self) -> Tuple:
        """Create train/test split"""
        if self.combined_data is None:
            raise ValueError("No data loaded. Run load_datasets() first.")
        
        X = self.combined_data.drop('label', axis=1)
        y = self.combined_data['label']
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print("\n" + "=" * 60)
        print("Training/Test Split:")
        print(f"  Training set: {X_train.shape[0]} samples")
        print(f"  Test set: {X_test.shape[0]} samples")
        print(f"  Phishing ratio: {y.mean():.2%}")
        print("=" * 60)
        
        return (X_train, y_train), (X_test, y_test)

if __name__ == '__main__':
    # Dataset paths from kagglehub download
    WEB_PATH = r"C:\Users\mns\.cache\kagglehub\datasets\shashwatwork\web-page-phishing-detection-dataset\versions\2\Phishing_Legitimate_full.csv"
    EMAIL_PATH = r"C:\Users\mns\.cache\kagglehub\datasets\naserabdullahalam\phishing-email-dataset\versions\1\Phishing_Email.csv"
    
    # Process datasets
    processor = PhishingDatasetProcessor()
    processor.load_datasets(WEB_PATH, EMAIL_PATH)
    
    # Save processed data
    processor.save_processed_data('processed_phishing_data.csv')
    
    # Create training data
    (X_train, y_train), (X_test, y_test) = processor.create_training_data()
    
    print("\n✓ Data preparation complete!")
    print("  Next step: Run train_model.py to train the ML model")
