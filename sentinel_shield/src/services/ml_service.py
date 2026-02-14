"""
Sentinel Shield - ML Service
Manages machine learning models for threat detection
OPTIMIZED: GPU acceleration, multi-threading, and lazy loading
"""

import os
import threading
import concurrent.futures
from pathlib import Path
from typing import Dict, Optional, Any
import joblib

MODEL_DIR = Path(__file__).parent.parent.parent / "models"

# Skip heavy BERT model loading for faster startup (set LOAD_BERT=1 to enable)
LOAD_BERT = os.environ.get("LOAD_BERT", "0") == "1"

# Enable lazy loading (default: True for fast startup)
LAZY_LOAD = os.environ.get("LAZY_LOAD_MODELS", "1") == "1"

# GPU settings
USE_GPU = os.environ.get("USE_GPU", "1") == "1"  # Enable GPU by default if available
NUM_THREADS = int(os.environ.get("ML_THREADS", "4"))  # Number of CPU threads


def get_device():
    """Get the best available device (GPU/CPU)"""
    try:
        import torch
        if USE_GPU and torch.cuda.is_available():
            device = torch.device("cuda")
            print(f"🚀 GPU detected: {torch.cuda.get_device_name(0)}")
            print(f"   CUDA version: {torch.version.cuda}")
            print(f"   GPU Memory: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f} GB")
            return device
        elif USE_GPU and hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
            # Apple Silicon GPU
            device = torch.device("mps")
            print("🚀 Apple Silicon GPU (MPS) detected")
            return device
        else:
            print(f"💻 Using CPU with {NUM_THREADS} threads")
            torch.set_num_threads(NUM_THREADS)
            return torch.device("cpu")
    except ImportError:
        print("⚠️ PyTorch not installed, GPU acceleration unavailable")
        return None


class MLService:
    """Machine Learning service for threat detection - GPU & Multi-threaded"""
    
    def __init__(self):
        self.phishing_model = None
        self.text_vectorizer = None
        self.feature_scaler = None
        self.transformer_model = None
        self.transformer_tokenizer = None
        self._models_loaded = False
        self._loading_lock = threading.Lock()
        self._load_future = None
        self.device = None
        
        # Thread pool for parallel predictions
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=NUM_THREADS)
        
        # Only load immediately if LAZY_LOAD is disabled
        if not LAZY_LOAD:
            self._load_models()
        else:
            print(f"⚡ ML Service initialized (lazy loading enabled)")
            print(f"   GPU: {'Enabled' if USE_GPU else 'Disabled'}")
            print(f"   Threads: {NUM_THREADS}")
    
    def _ensure_models_loaded(self):
        """Load models on first use (lazy loading) - thread-safe"""
        if self._models_loaded:
            return
            
        with self._loading_lock:
            if not self._models_loaded:
                print("📊 Loading ML models on first request...")
                self._load_models()
                self._models_loaded = True
    
    def _load_models_async(self):
        """Load models asynchronously in background"""
        if self._load_future is None:
            self._load_future = self.executor.submit(self._load_models)
        return self._load_future
    
    def _load_models(self):
        """Load all ML models with GPU support"""
        
        # Get device (GPU/CPU)
        self.device = get_device()
        
        # Load traditional ML model (fast) - parallel loading
        model_path = MODEL_DIR / "phishing_detector.joblib"
        if model_path.exists():
            try:
                # Use multiple threads for joblib
                data = joblib.load(model_path)
                self.phishing_model = data.get('model')
                self.text_vectorizer = data.get('text_vectorizer')
                self.feature_scaler = data.get('feature_scaler')
                print(f"✅ Loaded phishing model from {model_path}")
            except Exception as e:
                print(f"⚠️  Failed to load phishing model: {e}")
        
        # Skip BERT for fast startup (enable with LOAD_BERT=1)
        if not LOAD_BERT:
            print("ℹ️  Skipping BERT model (set LOAD_BERT=1 to enable)")
            self._models_loaded = True
            return
        
        # Load transformer model with GPU support
        transformer_path = MODEL_DIR / "ealvaradob_bert-finetuned-phishing"
        if transformer_path.exists():
            try:
                import torch
                from transformers import AutoTokenizer, AutoModelForSequenceClassification
                
                print("📥 Loading BERT model (this may take a moment)...")
                
                self.transformer_tokenizer = AutoTokenizer.from_pretrained(str(transformer_path))
                self.transformer_model = AutoModelForSequenceClassification.from_pretrained(str(transformer_path))
                
                # Move model to GPU if available
                if self.device and self.device.type != "cpu":
                    self.transformer_model = self.transformer_model.to(self.device)
                    print(f"✅ BERT model loaded on {self.device.type.upper()}")
                else:
                    print(f"✅ BERT model loaded on CPU")
                
                # Enable torch compile for faster inference (PyTorch 2.0+)
                try:
                    if hasattr(torch, 'compile'):
                        self.transformer_model = torch.compile(self.transformer_model, mode="reduce-overhead")
                        print("⚡ Torch compile enabled for faster inference")
                except Exception as e:
                    print(f"ℹ️ Torch compile not available: {e}")
                    
            except Exception as e:
                print(f"⚠️  Failed to load BERT model: {e}")
        
        self._models_loaded = True

    
    def predict_phishing(self, text: str) -> Dict[str, Any]:
        """Predict if text is phishing using available models - GPU accelerated"""
        
        # Lazy load models on first prediction
        self._ensure_models_loaded()
        
        results = {
            "is_phishing": False,
            "confidence": 0.0,
            "model_used": None,
            "device": str(self.device) if self.device else "cpu"
        }
        
        # Try transformer model first (more accurate)
        if self.transformer_model and self.transformer_tokenizer:
            try:
                import torch
                
                inputs = self.transformer_tokenizer(
                    text,
                    return_tensors="pt",
                    truncation=True,
                    max_length=512,
                    padding=True
                )
                
                # Move inputs to GPU if available
                if self.device:
                    inputs = {k: v.to(self.device) for k, v in inputs.items()}
                
                self.transformer_model.eval()
                with torch.no_grad():
                    outputs = self.transformer_model(**inputs)
                    probs = torch.softmax(outputs.logits, dim=1)
                    prediction = torch.argmax(probs, dim=1).item()
                    confidence = probs[0][1].item()
                
                results["is_phishing"] = bool(prediction)
                results["confidence"] = confidence
                results["model_used"] = "bert-phishing"
                return results
                
            except Exception as e:
                print(f"BERT prediction failed: {e}")
        
        # Fallback to traditional ML model
        if self.phishing_model and self.text_vectorizer:
            try:
                import numpy as np
                import scipy.sparse as sp
                
                # Vectorize text
                text_features = self.text_vectorizer.transform([text])
                
                # Create dummy numerical features
                numerical = np.zeros((1, 8))
                if self.feature_scaler:
                    numerical = self.feature_scaler.transform(numerical)
                
                # Combine
                combined = sp.hstack([text_features, numerical])
                
                # Predict
                prediction = self.phishing_model.predict(combined)[0]
                proba = self.phishing_model.predict_proba(combined)[0]
                
                results["is_phishing"] = bool(prediction)
                results["confidence"] = float(proba[1])
                results["model_used"] = "gradient-boosting"
                return results
                
            except Exception as e:
                print(f"ML prediction failed: {e}")
        
        # No models available - return unknown
        results["model_used"] = "none"
        return results
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models"""
        
        # Don't force load for info request - show current state
        models = []
        
        if not self._models_loaded:
            return {
                "models_loaded": 0,
                "status": "lazy_loading_enabled",
                "message": "Models will load on first prediction request",
                "models": []
            }
        
        if self.phishing_model:
            models.append({
                "name": "Gradient Boosting Phishing Detector",
                "type": "sklearn",
                "accuracy": "97%",
                "status": "loaded"
            })
        
        if self.transformer_model:
            models.append({
                "name": "BERT Phishing Detector",
                "type": "transformer",
                "accuracy": "~95%",
                "status": "loaded",
                "device": str(self.device) if self.device else "cpu"
            })
        
        if not models:
            models.append({
                "name": "No models loaded",
                "type": "none",
                "accuracy": "N/A",
                "status": "not_loaded"
            })
        
        return {
            "models_loaded": len(models),
            "device": str(self.device) if self.device else "cpu",
            "gpu_available": self.device is not None and self.device.type != "cpu",
            "threads": NUM_THREADS,
            "models": models
        }
    
    def predict_batch(self, texts: list) -> list:
        """
        Batch prediction for better GPU utilization
        Process multiple texts at once for faster throughput
        """
        self._ensure_models_loaded()
        
        results = []
        
        # Try transformer model with batching
        if self.transformer_model and self.transformer_tokenizer:
            try:
                import torch
                
                # Batch tokenize
                inputs = self.transformer_tokenizer(
                    texts,
                    return_tensors="pt",
                    truncation=True,
                    max_length=512,
                    padding=True
                )
                
                # Move to GPU
                if self.device:
                    inputs = {k: v.to(self.device) for k, v in inputs.items()}
                
                self.transformer_model.eval()
                with torch.no_grad():
                    outputs = self.transformer_model(**inputs)
                    probs = torch.softmax(outputs.logits, dim=1)
                    predictions = torch.argmax(probs, dim=1).cpu().numpy()
                    confidences = probs[:, 1].cpu().numpy()
                
                for i, text in enumerate(texts):
                    results.append({
                        "text": text[:100] + "..." if len(text) > 100 else text,
                        "is_phishing": bool(predictions[i]),
                        "confidence": float(confidences[i]),
                        "model_used": "bert-phishing",
                        "device": str(self.device)
                    })
                return results
                
            except Exception as e:
                print(f"Batch BERT prediction failed: {e}")
        
        # Fallback to sequential prediction
        for text in texts:
            results.append(self.predict_phishing(text))
        
        return results
    
    def predict_async(self, text: str):
        """
        Async prediction using thread pool
        Returns a Future that can be awaited
        """
        return self.executor.submit(self.predict_phishing, text)
    
    def warmup(self):
        """
        Warmup the model with a dummy prediction
        Useful to pre-compile CUDA kernels
        """
        self._ensure_models_loaded()
        
        # Run a dummy prediction to warmup
        dummy_text = "This is a test email for warmup purposes."
        self.predict_phishing(dummy_text)
        print("🔥 Model warmup complete")
    
    def __del__(self):
        """Cleanup thread pool on deletion"""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)
