# py -3.12 -m venv .venv
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# .\.venv\Scripts\activate
# python install.py

# scripts/install.py
import subprocess
import sys
import os
import shutil

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(PROJECT_ROOT)
os.chdir(PROJECT_ROOT)

def run_setup():
    print("=" * 60)
    print("Email Threat Detection Platform - Unified Installer")
    print("=" * 60)

    has_gpu = shutil.which("nvidia-smi") is not None
    default_choice = "y" if has_gpu else "n"
    
    print(f"[!] Hardware check: {'NVIDIA GPU detected' if has_gpu else 'No dedicated NVIDIA GPU found'}.")
    choice = input(f"Enable CUDA GPU acceleration? (y/n) [Default: {default_choice}]: ").strip().lower() or default_choice

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

    print("\n[+] Installing platform dependencies from requirements.txt...")
    # Because of os.chdir, pip correctly finds the requirements.txt in the root directory
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
    ])

    models_dir = os.path.join("models")
    has_models = os.path.exists(models_dir) and len(os.listdir(models_dir)) > 0

    if not has_models:
        print("\n" + "=" * 60)
        print("🧠 AI Model Weights Missing")
        print("=" * 60)
        dl_choice = input("Download required local models now (DistilBERT & Qwen 1.5B)? (y/n) [y]: ").strip().lower() or "y"
        if dl_choice in ["y", "yes"]:
            subprocess.check_call([sys.executable, os.path.join("scripts", "setup_models.py")])
        else:
            print("[!] Skipping model download. NLP classification will remain disabled until models exist.")

    print("\n[✓] Environment setup completed successfully.")

if __name__ == "__main__":
    run_setup()