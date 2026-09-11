# scripts/ingestion_daemon.py
import sys
import os
import signal

import logging
logging.getLogger("streamlit.runtime.scriptrunner_utils.script_run_context").setLevel(logging.ERROR)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(PROJECT_ROOT)
os.chdir(PROJECT_ROOT)

import time
import warnings
warnings.filterwarnings("ignore", message=".*missing ScriptRunContext.*")

from ui.upload import process_raw_eml_bytes, SPOOL_DIR

print("=" * 60)
print("🛡️ Enterprise Ingestion Daemon Active")
print(f"📡 Monitoring '{SPOOL_DIR}/' for incoming traffic...")
print("⚠️  Press Ctrl+C to initiate a safe shutdown sequence.")
print("=" * 60)

# 1. Global flag to control the loop
shutdown_requested = False

# 2. Signal handler to catch Ctrl+C gracefully
def safe_shutdown(signum, frame):
    global shutdown_requested
    print("\n\n[!] Shutdown signal received. Finishing current file before exiting...")
    shutdown_requested = True

signal.signal(signal.SIGINT, safe_shutdown)

def run_daemon():
    while not shutdown_requested:
        pending_files = [f for f in os.listdir(SPOOL_DIR) if f.endswith(".eml")]
        
        if pending_files:
            for fname in pending_files:
                if shutdown_requested:
                    break # Break the for-loop if shutdown was requested mid-batch
                    
                fpath = os.path.join(SPOOL_DIR, fname)
                try:
                    with open(fpath, "rb") as f:
                        f_bytes = f.read()
                    
                    print(f"[*] Analyzing AI for: {fname}...")
                    
                    ok, cid, data = process_raw_eml_bytes(fname, f_bytes)
                    
                    if ok:
                        print(f"    ✅ Success: Logged as {cid}")
                    else:
                        print(f"    ❌ Blocked: {data.get('error', 'Unknown Error')}")
                        
                    os.remove(fpath)
                    
                except Exception as e:
                    print(f"    💥 Fatal Watchdog fail on {fname}: {e}")
                    
            if not shutdown_requested:
                print("-" * 40)
            
        time.sleep(3)
        
    print("[✓] Daemon successfully terminated without data corruption.")

if __name__ == "__main__":
    run_daemon()