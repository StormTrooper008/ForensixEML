# logic/classifier.py
import os
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import torch.nn.functional as F

MODEL_PATH = "models/distilbert-phishing"

class LocalPhishingClassifier:
    def __init__(self):
        self.tokenizer = None
        self.model = None
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self._load_model()

    def _load_model(self):
        """Loads model and tokenizer into memory once to avoid reload latency."""
        try:
            print(f"Loading local DistilBERT model on {self.device}...")
            self.tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
            self.model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
            self.model.to(self.device)
            self.model.eval()
            print("DistilBERT model loaded successfully.")
        except Exception as e:
            print(f"Warning: Could not load local model weights: {e}")

    def predict(self, text: str) -> dict:
        """Runs inference on email text to calculate phishing probability."""
        if not self.model or not self.tokenizer:
            return {"confidence": 0.0, "label": "MODEL_UNAVAILABLE"}

        try:
            # Truncate text to fit model max length safely
            inputs = self.tokenizer(
                text, 
                padding=True, 
                truncation=True, 
                max_length=512, 
                return_tensors="pt"
            ).to(self.device)

            with torch.no_grad():
                outputs = self.model(**inputs)
                probs = F.softmax(outputs.logits, dim=-1)
                
            # Assuming binary classification: Index 0 = Safe, Index 1 = Phishing (adjust if multilabel)
            phish_prob = float(probs[0][1].item()) if probs.shape[-1] > 1 else float(probs[0][0].item())
            
            return {
                "phishing_probability": round(phish_prob * 100, 2),
                "is_phishing": phish_prob > 0.5
            }
        except Exception as e:
            print(f"Inference error: {e}")
            return {"confidence": 0.0, "label": "ERROR"}

# Global singleton instance so it only loads once when the app starts
classifier = LocalPhishingClassifier()

def run_local_classifier(text_content: str) -> dict:
    return classifier.predict(text_content)