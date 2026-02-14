"""
Fast Phishing Detection using Pre-trained Models
Uses existing models from HuggingFace - no training required!
"""

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
import warnings
warnings.filterwarnings('ignore')

class FastPhishingDetector:
    """
    Uses pre-trained models that are already fine-tuned on phishing detection
    No training required - ready to use immediately!
    """
    
    def __init__(self):
        # Check for GPU
        self.device = 0 if torch.cuda.is_available() else -1
        device_name = "GPU: " + torch.cuda.get_device_name(0) if self.device == 0 else "CPU"
        print(f"🔧 Using: {device_name}")
        
        # Load pre-trained model (already trained on phishing emails!)
        print("\n📥 Loading pre-trained phishing detector...")
        print("   Model: ealvaradob/bert-finetuned-phishing")
        
        try:
            self.classifier = pipeline(
                "text-classification",
                model="ealvaradob/bert-finetuned-phishing",
                device=self.device,
                max_length=512,
                truncation=True
            )
            print("✅ Model loaded successfully!")
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            print("   Falling back to smaller model...")
            self.classifier = pipeline(
                "text-classification",
                model="mrm8488/bert-mini-finetuned-phishing-email-detection",
                device=self.device,
                max_length=512,
                truncation=True
            )
            print("✅ Fallback model loaded!")
    
    def predict(self, text):
        """
        Predict if text is phishing
        Returns: dict with is_phishing, confidence, threat_score
        """
        if isinstance(text, list):
            results = []
            for t in text:
                result = self.classifier(t)[0]
                results.append(self._format_result(result))
            return results
        else:
            result = self.classifier(text)[0]
            return self._format_result(result)
    
    def _format_result(self, result):
        """Format classifier output"""
        # Check if label indicates phishing
        is_phishing = 'phish' in result['label'].lower() or result['label'] == 'LABEL_1'
        confidence = result['score']
        
        # If model predicts "safe" with high confidence, invert for phishing
        if not is_phishing:
            confidence = 1 - confidence
            is_phishing = confidence > 0.5
        
        return {
            'is_phishing': is_phishing,
            'confidence': confidence,
            'threat_score': int(confidence * 100),
            'label': result['label']
        }
    
    def batch_predict(self, texts, batch_size=8):
        """
        Predict multiple texts efficiently using batching
        Much faster than one-by-one prediction
        """
        print(f"\n🔄 Processing {len(texts)} texts in batches of {batch_size}...")
        results = self.classifier(texts, batch_size=batch_size)
        return [self._format_result(r) for r in results]


def test_detector():
    """Test the detector with sample emails"""
    print("=" * 70)
    print("🛡️  PHISHING DETECTOR - Using Pre-trained Models")
    print("=" * 70)
    
    detector = FastPhishingDetector()
    
    test_emails = [
        "URGENT: Your PayPal account has been limited. Click here immediately to verify: http://paypa1-security.com/verify",
        "Hi team, please review the attached quarterly report before tomorrow's meeting. Thanks!",
        "Congratulations! You've won $5,000,000 in the Microsoft Lottery! Send your bank details to claim your prize.",
        "Your Amazon order #123-4567890-1234567 has shipped and will arrive Thursday. Track your package here.",
        "FINAL NOTICE: Your account will be closed in 24 hours unless you update your password at www.bank-secure.tk",
        "Hey John, can you send me the slides from yesterday's presentation? Need them for my report.",
        "Dear Customer, We have detected suspicious activity on your account. Verify your identity now or face permanent suspension.",
        "Meeting rescheduled to 3pm today in Conference Room B. See calendar invite for details."
    ]
    
    print("\n🧪 TESTING ON SAMPLE EMAILS")
    print("="*70)
    
    # Test batch prediction (faster)
    results = detector.batch_predict(test_emails)
    
    for email, result in zip(test_emails, results):
        status = "🚨 PHISHING" if result['is_phishing'] else "✅ SAFE"
        print(f"\n{status} (Threat Score: {result['threat_score']}/100)")
        print(f"📧 {email[:65]}...")
        print(f"   Confidence: {result['confidence']:.1%}")
    
    print("\n" + "="*70)
    print("✅ DETECTION COMPLETE!")
    print("="*70)
    
    # Save detector for API use
    print("\n💾 Detector ready for API integration")
    return detector


if __name__ == "__main__":
    detector = test_detector()
