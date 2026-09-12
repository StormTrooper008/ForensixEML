# logic/ai_agent.py
import json
import os
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from typing import Dict, Any

QWEN_MODEL_PATH = "models/Qwen2.5-1.5B-Instruct" 

class LocalQwenExplainer:
    def __init__(self) -> None:
        self.tokenizer: Any = None
        self.model: Any = None
        self._load_model()

    def _load_model(self) -> None:
        if not os.path.exists(QWEN_MODEL_PATH):
            print(f"[!] Qwen model weights not found at '{QWEN_MODEL_PATH}'. AI narrative generation disabled.")
            return

        try:
            device_str = "cuda" if torch.cuda.is_available() else "cpu"
            print(f"Loading Qwen 1.5B on {device_str}...")
            
            self.tokenizer = AutoTokenizer.from_pretrained(QWEN_MODEL_PATH)
            
            if device_str == "cuda":
                self.model = AutoModelForCausalLM.from_pretrained(
                    QWEN_MODEL_PATH, dtype=torch.float16, device_map="auto"
                )
            else:
                self.model = AutoModelForCausalLM.from_pretrained(
                    QWEN_MODEL_PATH, dtype=torch.float32
                )
                
            self.model.eval()
            print("Qwen 1.5B loaded successfully.")
        except Exception as e:
            print(f"Warning: Could not load Qwen model: {e}")

    def generate_summary(self, telemetry_data: Dict[str, Any]) -> str:
        # Professional fallback message if model weights are missing
        if self.model is None or self.tokenizer is None:
            return (
                "ℹ️ **AI Threat Briefing Unavailable:** Local generative model weights (Qwen 1.5B) "
                "are not installed. Please verify the `models/Qwen2.5-1.5B-Instruct` directory "
                "or run `python scripts/setup_models.py` to enable automated narrative analysis."
            )
        
        safe_telemetry = {
            "distilbert_threat_confidence": f"{telemetry_data.get('local_ai', {}).get('phishing_probability', 0)}%",
            "email_message_preview": telemetry_data.get("decomp", {}).get("body_preview", "No text"),
            "suspicious_attachments": [a["filename"] for a in telemetry_data.get("decomp", {}).get("attachments", []) if a.get("is_risky")],
            "internal_spoofing_detected": telemetry_data.get("intel", {}).get("is_spoofing", False)
        }
        
        prompt = f"""<|im_start|>system
You are an expert Cybersecurity Analyst. Review the email forensic telemetry. 
Write a punchy, 3-sentence executive summary explaining exactly WHY this email is a threat. 
Mention the message text, DistilBERT score, and any attachments or spoofing.<|im_end|>
<|im_start|>user
Telemetry: {json.dumps(safe_telemetry)}<|im_end|>
<|im_start|>assistant
"""
        try:
            device_str = "cuda" if torch.cuda.is_available() else "cpu"
            inputs = self.tokenizer(prompt, return_tensors="pt").to(device_str)
            outputs = self.model.generate(
                **inputs, 
                max_new_tokens=150, 
                temperature=0.3,
                do_sample=True
            )
            
            input_length = inputs.input_ids.shape[1]
            response_text = self.tokenizer.decode(outputs[0][input_length:], skip_special_tokens=True)
            return response_text.strip()
        except Exception as e:
            return f"❌ Qwen Generation Error: {str(e)}"

# --- GLOBAL SINGLETON ---
_qwen_instance = None

def get_qwen():
    global _qwen_instance
    if _qwen_instance is None:
        _qwen_instance = LocalQwenExplainer()
    return _qwen_instance

def generate_incident_summary(telemetry_data: Dict[str, Any]) -> Dict[str, Any]:
    summary_text = get_qwen().generate_summary(telemetry_data)
    return {
        "ai_score": telemetry_data.get("risk_score", 0), 
        "ai_summary": summary_text
    }