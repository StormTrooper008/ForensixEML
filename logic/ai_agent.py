# logic/ai_agent.py
import json
import torch
import streamlit as st
from transformers import AutoModelForCausalLM, AutoTokenizer
from typing import Dict, Any

QWEN_MODEL_PATH = "models/Qwen2.5-1.5B-Instruct" 

class LocalQwenExplainer:
    def __init__(self) -> None:
        self.tokenizer: Any = None
        self.model: Any = None
        self._load_model()

    def _load_model(self) -> None:
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
        if self.model is None or self.tokenizer is None:
            return "⚠️ Qwen unavailable. DistilBERT applied without narrative."
        
        # SURGICAL EXTRACTION: Give Qwen exactly what it needs to write a smart summary without blowing up RAM
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
            outputs = self.model.generate(**inputs, max_new_tokens=150, temperature=0.3)
            
            input_length = inputs.input_ids.shape[1]
            response_text = self.tokenizer.decode(outputs[0][input_length:], skip_special_tokens=True)
            return response_text.strip()
        except Exception as e:
            return f"❌ Qwen Generation Error: {str(e)}"

# --- CACHE THE MODEL SO STREAMLIT DOESN'T FREEZE ON RELOAD ---
@st.cache_resource(show_spinner="Waking up Qwen 1.5B AI Agent...")
def get_qwen():
    return LocalQwenExplainer()

def generate_incident_summary(telemetry_data: Dict[str, Any]) -> Dict[str, Any]:
    summary_text = get_qwen().generate_summary(telemetry_data)
    return {
        "ai_score": telemetry_data.get("risk_score", 0), 
        "ai_summary": summary_text
    }