from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import re
from typing import Optional
import os

app = FastAPI(title="Anti-Fraud ML Service", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load trained model
MODEL_PATH = os.path.join(os.path.dirname(__file__), '../models/phishing_detector.joblib')
try:
    model = joblib.load(MODEL_PATH)
    print(f"✓ Model loaded from: {MODEL_PATH}")
except Exception as e:
    print(f"✗ Failed to load model: {e}")
    model = None

class EmailAnalysisRequest(BaseModel):
    subject: str
    body: str
    sender: str
    sender_name: Optional[str] = None

class EmailAnalysisResponse(BaseModel):
    is_phishing: bool
    threat_score: int
    confidence: float
    ml_prediction: str
    features: dict

def extract_features(email: EmailAnalysisRequest) -> dict:
    """Extract features from email for analysis"""
    text = f"{email.subject} {email.body}"
    
    # URL patterns
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    
    # IP address in URL
    has_ip_url = bool(re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text))
    
    # Suspicious patterns
    urgency_words = ['urgent', 'immediately', 'act now', 'limited time', 'expire', 'suspended', 'verify', 'confirm', 'update']
    sensitive_words = ['password', 'credit card', 'ssn', 'social security', 'bank account', 'verify account']
    
    urgency_count = sum(1 for word in urgency_words if word in text.lower())
    sensitive_count = sum(1 for word in sensitive_words if word in text.lower())
    
    # Character substitution patterns
    char_substitution_patterns = [
        (r'rn', 'm'),  # rn looks like m
        (r'vv', 'w'),  # vv looks like w
        (r'cl', 'd'),  # cl looks like d
    ]
    has_char_substitution = any(re.search(pattern[0], text.lower()) for pattern in char_substitution_patterns)
    
    # Check for mismatched sender
    sender_mismatch = False
    if email.sender_name:
        # Extract name from email body signature
        signature_match = re.search(r'(?:regards|sincerely|best|thanks),?\s*\n?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)', email.body, re.IGNORECASE)
        if signature_match:
            signature_name = signature_match.group(1).strip().lower()
            sender_name_lower = email.sender_name.lower()
            sender_mismatch = signature_name not in sender_name_lower and sender_name_lower not in signature_name
    
    features = {
        'text_length': len(text),
        'url_count': len(urls),
        'has_ip_url': has_ip_url,
        'urgency_count': urgency_count,
        'sensitive_count': sensitive_count,
        'has_char_substitution': has_char_substitution,
        'sender_mismatch': sender_mismatch,
        'has_attachment_mention': bool(re.search(r'attach|download|file|document', text.lower())),
        'exclamation_count': text.count('!'),
        'question_count': text.count('?'),
        'uppercase_ratio': sum(1 for c in text if c.isupper()) / max(len(text), 1),
    }
    
    return features

@app.post("/predict", response_model=EmailAnalysisResponse)
async def predict(email: EmailAnalysisRequest):
    """Analyze email and predict if it's phishing"""
    
    if model is None:
        raise HTTPException(status_code=500, detail="Model not loaded")
    
    try:
        # Extract features
        features = extract_features(email)
        
        # Prepare text for model
        text = f"{email.subject} {email.body}"
        
        # Get prediction
        prediction = model.predict([text])[0]
        probabilities = model.predict_proba([text])[0]
        
        # Calculate confidence and threat score
        confidence = float(probabilities[1])  # Probability of phishing
        threat_score = int(confidence * 100)
        
        # Adjust threat score based on features
        if features['has_char_substitution']:
            threat_score = min(100, threat_score + 15)
        if features['sender_mismatch']:
            threat_score = min(100, threat_score + 20)
        if features['has_ip_url']:
            threat_score = min(100, threat_score + 10)
        if features['urgency_count'] > 2:
            threat_score = min(100, threat_score + 10)
        
        is_phishing = prediction == 1 or threat_score >= 70
        
        return EmailAnalysisResponse(
            is_phishing=is_phishing,
            threat_score=threat_score,
            confidence=confidence,
            ml_prediction="phishing" if prediction == 1 else "legitimate",
            features=features
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "model_path": MODEL_PATH
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Anti-Fraud ML Service",
        "version": "1.0.0",
        "endpoints": [
            "/predict - POST - Analyze email",
            "/health - GET - Health check"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
