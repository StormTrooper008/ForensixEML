"""
Air-Gapped Threat Detection Platform - Model Downloader
Downloads local transformer weights required for offline inference.
"""

import os
import sys
from huggingface_hub import snapshot_download

MODELS = [
    {
        "repo_id": "cybersectony/phishing-email-detection-distilbert_v2.4.1",
        "local_dir": os.path.join("models", "distilbert-phishing"),
        "description": "DistilBERT Phishing Gatekeeper (~300 MB)"
    },
    {
        "repo_id": "Qwen/Qwen2.5-1.5B-Instruct",
        "local_dir": os.path.join("models", "Qwen2.5-1.5B-Instruct"),
        "description": "Qwen 2.5 1.5B Narrative Explainer (~3.2 GB)"
    }
]

def download_all_models():
    print("=" * 60)
    print("Initializing Local AI Ensemble Model Ingestion")
    print("=" * 60)
    
    # 1. Storage Warning & Confirmation Prompt
    print("⚠️  STORAGE WARNING: This process will download approximately 5 GB of neural network weights to your local machine.")
    print("This ensures 100% air-gapped, offline operation for the threat detection platform.\n")
    
    choice = input("Do you have enough disk space and wish to proceed? (y/n): ").strip().lower()
    
    # 2. Abort Logic
    if choice not in ['y', 'yes']:
        print("\n[!] Download aborted by user. You can run this script later when space is available.")
        sys.exit(0)

    # 3. Execution Logic
    for item in MODELS:
        print(f"\n[+] Fetching {item['description']}...")
        print(f"    Source : {item['repo_id']}")
        print(f"    Target : {item['local_dir']}")
        
        os.makedirs(item['local_dir'], exist_ok=True)
        
        try:
            snapshot_download(
                repo_id=item["repo_id"],
                local_dir=item["local_dir"],
                ignore_patterns=["*.msgpack", "*.h5", "*.ot"]
            )
            print(f"[✓] {item['description']} downloaded successfully.")
        except Exception as e:
            print(f"[X] Failed to download {item['description']}. Error: {e}")

    print("\n" + "=" * 60)
    print("All models downloaded. Platform is ready for air-gapped operation.")
    print("=" * 60)

if __name__ == "__main__":
    download_all_models()