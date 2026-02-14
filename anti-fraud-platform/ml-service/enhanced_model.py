"""
Enhanced Phishing Detection with Pre-trained Models and GPU Support
Uses multiple datasets and pre-trained BERT models for better accuracy
"""

import os
import pandas as pd
import numpy as np
from pathlib import Path
import kagglehub
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments
from datasets import Dataset
import warnings
warnings.filterwarnings('ignore')

class EnhancedPhishingDetector:
    """
    Multi-dataset phishing detector with pre-trained models
    Features:
    - Multiple Kaggle datasets
    - Pre-trained BERT models from HuggingFace
    - GPU acceleration (if available)
    - Multi-threading for data processing
    """
    
    def __init__(self, use_gpu=True):
        self.use_gpu = use_gpu and torch.cuda.is_available()
        self.device = "cuda" if self.use_gpu else "cpu"
        print(f"🔧 Using device: {self.device}")
        if self.use_gpu:
            print(f"🚀 GPU: {torch.cuda.get_device_name(0)}")
            print(f"💾 GPU Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB")
        
        self.datasets_info = [
            {
                'name': 'web-phishing',
                'kaggle_id': 'shashwatwork/web-page-phishing-detection-dataset',
                'text_col': 'text_combined',
                'label_col': 'phishing'
            },
            {
                'name': 'email-phishing',
                'kaggle_id': 'naserabdullahalam/phishing-email-dataset',
                'text_col': 'Email Text',
                'label_col': 'Email Type'
            },
            {
                'name': 'ceas-phishing',
                'kaggle_id': 'subhajournal/phishingemails',
                'text_col': 'Email Text',
                'label_col': 'Email Type'
            }
        ]
        
        # Pre-trained models optimized for phishing detection
        self.pretrained_models = [
            'ealvaradob/bert-finetuned-phishing',  # Already fine-tuned on phishing
            'mrm8488/bert-mini-finetuned-phishing-email-detection',  # Lightweight
            'distilbert-base-uncased',  # General purpose, faster than BERT
        ]
        
        self.model = None
        self.tokenizer = None
        
    def download_all_datasets(self):
        """Download all available datasets in parallel"""
        print("\n📥 Downloading datasets from Kaggle...")
        
        def download_dataset(dataset_info):
            try:
                print(f"  ⬇️  Downloading {dataset_info['name']}...")
                path = kagglehub.dataset_download(dataset_info['kaggle_id'])
                dataset_info['path'] = path
                print(f"  ✅ {dataset_info['name']}: {path}")
                return dataset_info
            except Exception as e:
                print(f"  ❌ Failed to download {dataset_info['name']}: {e}")
                return None
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            results = list(executor.map(download_dataset, self.datasets_info))
        
        # Filter successful downloads
        self.datasets_info = [r for r in results if r is not None]
        print(f"\n✅ Downloaded {len(self.datasets_info)} datasets")
        
    def load_and_combine_datasets(self):
        """Load all datasets and combine them"""
        print("\n📊 Loading and combining datasets...")
        all_data = []
        
        for ds_info in self.datasets_info:
            try:
                # Find CSV files in dataset directory
                dataset_path = Path(ds_info['path'])
                csv_files = list(dataset_path.rglob('*.csv'))
                
                if not csv_files:
                    print(f"  ⚠️  No CSV files found in {ds_info['name']}")
                    continue
                
                print(f"  📄 Loading {ds_info['name']} from {csv_files[0].name}...")
                df = pd.read_csv(csv_files[0])
                
                # Standardize columns
                text_col = None
                label_col = None
                
                # Find text column (case-insensitive)
                for col in df.columns:
                    if 'text' in col.lower() or 'email' in col.lower() or 'message' in col.lower():
                        text_col = col
                        break
                
                # Find label column
                for col in df.columns:
                    if 'phishing' in col.lower() or 'label' in col.lower() or 'type' in col.lower():
                        label_col = col
                        break
                
                if text_col and label_col:
                    # Create standardized dataframe
                    subset = pd.DataFrame({
                        'text': df[text_col].fillna(''),
                        'label': df[label_col]
                    })
                    
                    # Standardize labels to 0 (safe) and 1 (phishing)
                    if subset['label'].dtype == 'object':
                        subset['label'] = subset['label'].apply(
                            lambda x: 1 if 'phish' in str(x).lower() or 'spam' in str(x).lower() else 0
                        )
                    
                    all_data.append(subset)
                    print(f"  ✅ {ds_info['name']}: {len(subset):,} samples")
                else:
                    print(f"  ⚠️  Could not find text/label columns in {ds_info['name']}")
                    print(f"     Columns: {df.columns.tolist()}")
                    
            except Exception as e:
                print(f"  ❌ Error loading {ds_info['name']}: {e}")
        
        if not all_data:
            raise ValueError("No datasets could be loaded!")
        
        # Combine all datasets
        combined = pd.concat(all_data, ignore_index=True)
        
        # Remove duplicates and empty texts
        combined = combined[combined['text'].str.len() > 10]
        combined = combined.drop_duplicates(subset=['text'])
        
        print(f"\n✅ Combined dataset: {len(combined):,} samples")
        print(f"   Safe emails: {(combined['label']==0).sum():,}")
        print(f"   Phishing emails: {(combined['label']==1).sum():,}")
        
        return combined
    
    def load_pretrained_model(self, model_name=None):
        """Load a pre-trained phishing detection model"""
        if model_name is None:
            model_name = self.pretrained_models[0]  # Use best one by default
        
        print(f"\n🤖 Loading pre-trained model: {model_name}")
        
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_name)
            self.model.to(self.device)
            print(f"✅ Model loaded successfully on {self.device}")
            return True
        except Exception as e:
            print(f"❌ Failed to load {model_name}: {e}")
            return False
    
    def prepare_dataset_for_training(self, df, test_size=0.2):
        """Prepare dataset for HuggingFace training"""
        print(f"\n🔄 Preparing dataset for training...")
        
        # Split data
        train_df, test_df = train_test_split(df, test_size=test_size, random_state=42, stratify=df['label'])
        
        # Convert to HuggingFace Dataset
        train_dataset = Dataset.from_pandas(train_df[['text', 'label']])
        test_dataset = Dataset.from_pandas(test_df[['text', 'label']])
        
        # Tokenize with multi-processing
        def tokenize_function(examples):
            return self.tokenizer(
                examples['text'],
                padding='max_length',
                truncation=True,
                max_length=512
            )
        
        print("  🔄 Tokenizing training data...")
        train_dataset = train_dataset.map(tokenize_function, batched=True, num_proc=4)
        
        print("  🔄 Tokenizing test data...")
        test_dataset = test_dataset.map(tokenize_function, batched=True, num_proc=4)
        
        print(f"✅ Training samples: {len(train_dataset):,}")
        print(f"✅ Test samples: {len(test_dataset):,}")
        
        return train_dataset, test_dataset
    
    def train(self, train_dataset, test_dataset, output_dir='./models/phishing-detector'):
        """Fine-tune the model on phishing data"""
        print(f"\n🎯 Starting training...")
        
        training_args = TrainingArguments(
            output_dir=output_dir,
            evaluation_strategy="epoch",
            save_strategy="epoch",
            learning_rate=2e-5,
            per_device_train_batch_size=16 if self.use_gpu else 8,
            per_device_eval_batch_size=16 if self.use_gpu else 8,
            num_train_epochs=3,
            weight_decay=0.01,
            load_best_model_at_end=True,
            metric_for_best_model="accuracy",
            fp16=self.use_gpu,  # Use mixed precision on GPU
            dataloader_num_workers=4,  # Multi-threading
            logging_steps=100,
            save_total_limit=2,
        )
        
        def compute_metrics(eval_pred):
            predictions, labels = eval_pred
            predictions = np.argmax(predictions, axis=1)
            return {
                'accuracy': accuracy_score(labels, predictions),
            }
        
        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=test_dataset,
            compute_metrics=compute_metrics,
        )
        
        # Train
        print("🚀 Training started...")
        trainer.train()
        
        # Evaluate
        print("\n📊 Evaluating model...")
        results = trainer.evaluate()
        print(f"✅ Test Accuracy: {results['eval_accuracy']:.4f}")
        
        # Save model
        print(f"\n💾 Saving model to {output_dir}...")
        trainer.save_model(output_dir)
        self.tokenizer.save_pretrained(output_dir)
        
        return results
    
    def predict(self, texts):
        """Predict phishing for a list of texts"""
        if isinstance(texts, str):
            texts = [texts]
        
        # Tokenize
        inputs = self.tokenizer(texts, padding=True, truncation=True, max_length=512, return_tensors="pt")
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        # Predict
        self.model.eval()
        with torch.no_grad():
            outputs = self.model(**inputs)
            probabilities = torch.softmax(outputs.logits, dim=1)
            predictions = torch.argmax(probabilities, dim=1)
        
        return {
            'predictions': predictions.cpu().numpy(),
            'probabilities': probabilities.cpu().numpy(),
            'is_phishing': predictions.cpu().numpy().tolist(),
            'confidence': probabilities[:, 1].cpu().numpy().tolist()
        }


def main():
    """Main training pipeline"""
    print("=" * 60)
    print("🛡️  ENHANCED PHISHING DETECTOR")
    print("=" * 60)
    
    # Initialize detector
    detector = EnhancedPhishingDetector(use_gpu=True)
    
    # Try to load pre-trained model first
    print("\n🔍 Attempting to use pre-trained model...")
    for model_name in detector.pretrained_models:
        if detector.load_pretrained_model(model_name):
            break
    
    if detector.model is None:
        print("❌ No pre-trained models available. Please install transformers and try again.")
        return
    
    # Download datasets
    detector.download_all_datasets()
    
    # Load and combine datasets
    combined_df = detector.load_and_combine_datasets()
    
    # Prepare for training
    train_dataset, test_dataset = detector.prepare_dataset_for_training(combined_df)
    
    # Train model
    results = detector.train(train_dataset, test_dataset)
    
    # Test predictions
    print("\n" + "="*60)
    print("🧪 TESTING PREDICTIONS")
    print("="*60)
    
    test_emails = [
        "Dear valued customer, your account will be suspended unless you verify your information immediately at http://suspicious-link.com",
        "Hi John, the meeting is scheduled for 3pm tomorrow in conference room B. See you there!",
        "URGENT: You have won $1,000,000! Click here to claim your prize now!",
        "Your Amazon order #12345 has been shipped and will arrive by Friday."
    ]
    
    for email in test_emails:
        result = detector.predict(email)
        print(f"\n📧 Email: {email[:80]}...")
        print(f"   {'🚨 PHISHING' if result['is_phishing'][0] else '✅ SAFE'} (confidence: {result['confidence'][0]:.2%})")
    
    print("\n" + "="*60)
    print("✅ TRAINING COMPLETE!")
    print("="*60)


if __name__ == "__main__":
    main()
