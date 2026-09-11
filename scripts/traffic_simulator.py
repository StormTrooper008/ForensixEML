# scripts/traffic_simulator.py
import sys
import os
import signal
import time
import random
import email.message
import email.utils
import warnings

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(PROJECT_ROOT)
os.chdir(PROJECT_ROOT)

warnings.filterwarnings("ignore", message=".*missing ScriptRunContext.*")

import torch
from logic.ai_agent import get_qwen


SPOOL_DIR = "inbox_spool"
MAX_SPOOL_SIZE = 50 
os.makedirs(SPOOL_DIR, exist_ok=True)

CAMPAIGN_IPS = ["185.220.101.5", "91.240.118.172", "103.145.12.89"]
EMPLOYEES = ["vikram.sharma@yourorg.com", "sneha.patel@yourorg.com", "finance-desk@yourorg.com"]

print("=" * 60)
print("🚀 Booting Live Enterprise Traffic Simulator...")
print("🧠 Loading Qwen 1.5B for dynamic threat generation...")
print("⚠️  Press Ctrl+C to initiate a safe shutdown sequence.")
print("=" * 60)

# --- SAFE SHUTDOWN LOGIC ---
shutdown_requested = False

def safe_shutdown(signum, frame):
    global shutdown_requested
    print("\n\n[!] Shutdown signal received. Finishing current file before exiting...")
    shutdown_requested = True

signal.signal(signal.SIGINT, safe_shutdown)
# ---------------------------

agent = get_qwen()

def generate_ai_lure(topic: str) -> str:
    prompt = f"<|im_start|>system\nYou are a red-team operator writing a realistic, 2-sentence phishing email body. Do not include subject lines or headers.<|im_end|>\n<|im_start|>user\nWrite a short, urgent email about: {topic}<|im_end|>\n<|im_start|>assistant\n"
    
    device = "cuda" if torch.cuda.is_available() else "cpu"
    inputs = agent.tokenizer(prompt, return_tensors="pt").to(device)
    # Added do_sample=True to prevent transformers crashing on temperature arguments
    outputs = agent.model.generate(**inputs, max_new_tokens=60, temperature=0.8, do_sample=True)
    
    input_length = inputs.input_ids.shape[1]
    return agent.tokenizer.decode(outputs[0][input_length:], skip_special_tokens=True).strip()

def run_simulator():
    case_number = 1
    while not shutdown_requested:
        current_files = len([f for f in os.listdir(SPOOL_DIR) if f.endswith('.eml')])
        if current_files >= MAX_SPOOL_SIZE:
            print(f"⏸️  Spool full ({MAX_SPOOL_SIZE}/{MAX_SPOOL_SIZE}). Waiting for platform ingestion...")
            time.sleep(10)
            continue

        is_attack = random.random() < 0.6  
        msg = email.message.EmailMessage()
        msg['To'] = random.choice(EMPLOYEES)
        msg['Date'] = email.utils.formatdate(localtime=True)
        msg['Message-ID'] = email.utils.make_msgid(domain="forensic-lab.local")
        
        if is_attack:
            topic = random.choice(["an overdue invoice", "mandatory HR compliance", "password expiry"])
            print(f"[!] Generating AI Attack Lure: {topic}...")
            body = generate_ai_lure(topic)
            origin_ip = random.choice(CAMPAIGN_IPS) if random.random() < 0.7 else f"{random.randint(11,210)}.{random.randint(1,254)}.1.1"
            msg['From'] = '"Admin Alert" <security@trusted-update.local>'
            msg['Subject'] = f"ACTION REQUIRED: {topic.title()}"
            msg.add_header('Received', f'from mailhost.threat-relay.net ([{origin_ip}]) by mx.yourorg.com; {email.utils.formatdate(localtime=True)}')
            filename = f"live_threat_{case_number:04d}.eml"
        else:
            print("[i] Generating Benign Traffic...")
            body = "Just a reminder that the all-hands meeting is at 3 PM today. See you there!"
            msg['From'] = '"Internal Comms" <comms@yourorg.com>'
            msg['Subject'] = "Meeting Reminder"
            msg.add_header('Received', f'from internal.yourorg.com ([192.168.1.50]) by mx.yourorg.com; {email.utils.formatdate(localtime=True)}')
            filename = f"live_benign_{case_number:04d}.eml"

        msg.set_content(body)
        
        filepath = os.path.join(SPOOL_DIR, filename)
        with open(filepath, "wb") as f:
            f.write(bytes(msg))
            
        print(f"✅ Dispatched: {filename} ({current_files + 1}/{MAX_SPOOL_SIZE})")
        case_number += 1
        
        # Responsive Sleep: Checks for shutdown every 1 second instead of freezing for 30s
        sleep_time = random.randint(10, 30)
        for _ in range(sleep_time):
            if shutdown_requested:
                break
            time.sleep(1)

    print("[✓] Traffic Simulator successfully terminated.")

if __name__ == "__main__":
    run_simulator()