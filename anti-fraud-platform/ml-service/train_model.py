import pandas as pd
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
from pathlib import Path
import scipy.sparse as sp

class PhishingDetector:
    """Advanced phishing detection model"""
    
    def __init__(self):
        self.text_vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3),
            min_df=2,
            max_df=0.95
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
        # Clean text data - replace NaN with empty string
        text_data = df['text'].fillna('').astype(str)
        
        # Text features (TF-IDF)
        text_features = self.text_vectorizer.fit_transform(text_data) if fit \
                       else self.text_vectorizer.transform(text_data)
        
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
        combined = sp.hstack([text_features, numerical_features])
        
        return combined
    
    def train(self, X_train, y_train, X_test, y_test):
        """Train the model"""
        print("\n" + "=" * 60)
        print("TRAINING PHISHING DETECTION MODEL")
        print("=" * 60)
        
        print("\nPreparing features...")
        X_train_features = self.prepare_features(X_train, fit=True)
        X_test_features = self.prepare_features(X_test, fit=False)
        
        print(f"  Feature dimensions: {X_train_features.shape}")
        
        print("\nTraining Gradient Boosting model...")
        self.model.fit(X_train_features, y_train)
        
        # Evaluate
        train_score = self.model.score(X_train_features, y_train)
        test_score = self.model.score(X_test_features, y_test)
        
        print(f"\n✓ Training accuracy: {train_score:.4f}")
        print(f"✓ Test accuracy: {test_score:.4f}")
        
        # Detailed evaluation
        y_pred = self.model.predict(X_test_features)
        
        print("\n" + "=" * 60)
        print("CLASSIFICATION REPORT")
        print("=" * 60)
        print(classification_report(y_test, y_pred, 
                                   target_names=['Legitimate', 'Phishing']))
        
        print("\n" + "=" * 60)
        print("CONFUSION MATRIX")
        print("=" * 60)
        cm = confusion_matrix(y_test, y_pred)
        print(f"True Negatives:  {cm[0][0]:>5}")
        print(f"False Positives: {cm[0][1]:>5}")
        print(f"False Negatives: {cm[1][0]:>5}")
        print(f"True Positives:  {cm[1][1]:>5}")
        
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
    
    def save(self, path: str = '../models/phishing_detector.joblib'):
        """Save model and preprocessors"""
        model_path = Path(path)
        model_path.parent.mkdir(exist_ok=True)
        
        joblib.dump({
            'model': self.model,
            'text_vectorizer': self.text_vectorizer,
            'feature_scaler': self.feature_scaler
        }, model_path)
        print(f"\n✓ Model saved to: {model_path.absolute()}")
    
    @staticmethod
    def load(path: str = '../models/phishing_detector.joblib'):
        """Load model and preprocessors"""
        detector = PhishingDetector()
        data = joblib.load(path)
        detector.model = data['model']
        detector.text_vectorizer = data['text_vectorizer']
        detector.feature_scaler = data['feature_scaler']
        print(f"✓ Model loaded from: {path}")
        return detector

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("ANTI-FRAUD PLATFORM - ML MODEL TRAINING")
    print("=" * 60)
    
    # Load processed data
    print("\nLoading processed data...")
    df = pd.read_csv('processed_phishing_data.csv')
    print(f"✓ Loaded {len(df)} samples")
    
    # Split features and labels
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Train/test split
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Create and train model
    detector = PhishingDetector()
    test_score = detector.train(X_train, y_train, X_test, y_test)
    
    # Save model
    detector.save('../models/phishing_detector.joblib')
    
    print("\n" + "=" * 60)
    print("✓ MODEL TRAINING COMPLETE!")
    print("=" * 60)
    print(f"  Final Test Accuracy: {test_score:.4f}")
    print(f"  Model Location: {Path('../models/phishing_detector.joblib').absolute()}")
    print("\n  Next step: Create FastAPI service to serve predictions")
    print("=" * 60)
