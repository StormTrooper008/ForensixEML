# scripts/ingestion_daemon.py
import sys
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(PROJECT_ROOT)
os.chdir(PROJECT_ROOT) # Forces execution context to the root directory

import time
import warnings
warnings.filterwarnings("ignore", message=".*missing ScriptRunContext.*")

from ui.upload import process_raw_eml_bytes, SPOOL_DIR

print("=" * 60)
print("🛡️ Enterprise Ingestion Daemon Active")
print(f"📡 Monitoring '{SPOOL_DIR}/' for incoming traffic...")
print("=" * 60)

def run_daemon():
    while True:
        pending_files = [f for f in os.listdir(SPOOL_DIR) if f.endswith(".eml")]
        
        if pending_files:
            for fname in pending_files:
                fpath = os.path.join(SPOOL_DIR, fname)
                try:
                    with open(fpath, "rb") as f:
                        f_bytes = f.read()
                    
                    print(f"[*] Analyzing AI for: {fname} (This may take a few seconds)...")
                    
                    ok, cid, data = process_raw_eml_bytes(fname, f_bytes)
                    
                    if ok:
                        print(f"    ✅ Success: Logged as {cid}")
                    else:
                        print(f"    ❌ Blocked: {data.get('error', 'Unknown Error')}")
                        
                    os.remove(fpath)
                    
                except Exception as e:
                    print(f"    💥 Fatal Watchdog fail on {fname}: {e}")
                    
            print("-" * 40)
            
        time.sleep(3)

if __name__ == "__main__":
    run_daemon()