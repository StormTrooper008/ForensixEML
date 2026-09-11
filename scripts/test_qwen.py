# scripts/test_qwen.py
import sys
import os

# 1. Force Python to recognize the parent root folder for imports (logic)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(PROJECT_ROOT)

# 2. Force the working directory to the root so relative paths (models/) work
os.chdir(PROJECT_ROOT)

import torch
from logic.ai_agent import get_qwen

print("1. Loading Qwen into memory...")
try:
    agent = get_qwen()
    print("2. Model loaded successfully.")
    
    prompt = "<|im_start|>system\nYou summarize threats.<|im_end|>\n<|im_start|>user\nTest summary.<|im_end|>\n<|im_start|>assistant\n"
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"3. Running inference on: {device}...")
    
    inputs = agent.tokenizer(prompt, return_tensors="pt").to(device)
    outputs = agent.model.generate(**inputs, max_new_tokens=20)
    
    result = agent.tokenizer.decode(outputs[0], skip_special_tokens=True)
    print(f"4. Success! Output length: {len(result)}")
except Exception as e:
    print(f"\n[!] FAILED: {e}")