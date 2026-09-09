# install.py
import subprocess
import sys
import shutil

def run_setup():
    print("=" * 60)
    print("Email Threat Detection Platform - Dependency Setup")
    print("=" * 60)

    has_gpu = shutil.which("nvidia-smi") is not None
    default_choice = "y" if has_gpu else "n"
    
    print(f"[!] Hardware check: {'NVIDIA GPU detected' if has_gpu else 'No dedicated NVIDIA GPU found'}.")
    choice = input(f"Enable CUDA GPU acceleration? (y/n) [Default: {default_choice}]: ").strip().lower() or default_choice

    # 1. Install Hardware-Specific PyTorch
    if choice in ["y", "yes"]:
        print("\n[+] Installing CUDA 12.4 PyTorch wheels (~2.5 GB)...")
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

    # 2. Install General Dependencies
    print("\n[+] Installing platform dependencies from requirements.txt...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    print("\n[✓] Environment setup completed successfully.")

if __name__ == "__main__":
    run_setup()



# pip install -r requirements.txt
# pip uninstall torch torchvision -y
# pip install torch torchvision --index-url https://download.pytorch.org/whl/cu124
