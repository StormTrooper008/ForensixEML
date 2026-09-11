# py -3.12 -m venv .venv
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# .\.venv\Scripts\activate
# python install.py

import subprocess
import sys
import os
import shutil

def run_setup():
    print("=" * 60)
    print("Email Threat Detection Platform - Unified Installer")
    print("=" * 60)

    # 1. Hardware Detection
    has_gpu = shutil.which("nvidia-smi") is not None
    default_choice = "y" if has_gpu else "n"
    
    print(f"[!] Hardware check: {'NVIDIA GPU detected' if has_gpu else 'No dedicated NVIDIA GPU found'}.")
    choice = input(f"Enable CUDA GPU acceleration? (y/n) [Default: {default_choice}]: ").strip().lower() or default_choice

    # 2. PyTorch Hardware Selection
    if choice in ["y", "yes"]:
        print("\n[+] Installing CUDA 12.4 PyTorch wheels...")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", 
            "torch", "torchvision", 
            "--index-url", "https://download.pytorch.org/whl/cu124"
        ])
    else:
        print("\n[+] Installing standard CPU PyTorch wheels (~200 MB)...")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", 
            "torch", "torchvision"
        ])

    # 3. Core Platform Dependencies
    print("\n[+] Installing platform dependencies from requirements.txt...")
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
    ])

    # 4. Air-Gapped Model Check
    models_dir = os.path.join(os.path.dirname(__file__), "models")
    has_models = os.path.exists(models_dir) and len(os.listdir(models_dir)) > 0

    if not has_models:
        print("\n" + "=" * 60)
        print("🧠 AI Model Weights Missing")
        print("=" * 60)
        dl_choice = input("Download required local models now (DistilBERT & Qwen 1.5B)? (y/n) [y]: ").strip().lower() or "y"
        if dl_choice in ["y", "yes"]:
            setup_script = os.path.join("tools", "setup_models.py")
            if not os.path.exists(setup_script):
                setup_script = "setup_models.py"
            subprocess.check_call([sys.executable, setup_script])
        else:
            print("[!] Skipping model download. NLP classification will remain disabled until models exist.")

    print("\n[✓] Environment setup completed successfully.")

if __name__ == "__main__":
    run_setup()