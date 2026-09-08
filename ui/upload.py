# --- ui/upload.py ---
import hashlib
import re
import streamlit as st
import json
import email
from email import policy

from logic.parser import parse_step1_headers
from logic.auth import run_protocol_checks
from logic.enrichment import get_ip_geolocation, enrich_hop_chain
from logic.heuristics import scan_body_heuristics
from logic.database import get_db_connection
from logic.intel import check_ledger_intelligence

def validate_rfc_structure(file_bytes: bytes) -> tuple[bool, str]:
    """Strictly validates RFC 5322 structure and mandatory email headers."""
    if not file_bytes or len(file_bytes.strip()) == 0:
        return False, "File is completely empty (0 bytes)."

    try:
        msg = email.message_from_bytes(file_bytes, policy=policy.default)
    except Exception as e:
        return False, f"MIME parser crash: {str(e)}"

    # 1. Mandatory Header Check
    from_header = msg.get("From", "")
    if not from_header:
        return False, "Corrupted EML: Missing mandatory 'From' header."

    # 2. Validate email structure in From header
    if "@" not in from_header or not re.search(r"[\w.-]+@[\w.-]+", from_header):
        return False, f"Corrupted EML: 'From' header contains no valid email address ({from_header})."

    # 3. Must contain at least one standard RFC timestamp/identifier header
    rfc_markers = ["Date", "Subject", "Message-ID", "Received"]
    found_markers = [m for m in rfc_markers if msg.get(m)]
    if not found_markers:
        return False, "Corrupted EML: Lacks standard RFC routing headers (No Date, Subject, or Message-ID)."

    return True, "Valid"

def render_upload():
    st.markdown("<h2>Forensic Ingestion Engine</h2>", unsafe_allow_html=True)
    st.caption("Strictly accepts RFC 822 / RFC 5322 compliant .eml files. Malformed files are rejected before processing.")
    
    uploaded_files = st.file_uploader("Drop case files here", type=["eml"], accept_multiple_files=True)
    
    if st.button("🚀 Confirm & Process Batch", type="primary"):
        if not uploaded_files:
            st.warning("No files provided.")
            return

        total_files = len(uploaded_files)
        progress_bar = st.progress(0, text="Initializing ingestion sandbox...")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        success_cases = []
        errors = []

        for idx, uf in enumerate(uploaded_files):
            progress_bar.progress((idx) / total_files, text=f"Inspecting '{uf.name}' ({idx + 1}/{total_files})...")
            
            try:
                f_bytes = uf.read()
                
                # 1. Strict Sandbox Validation
                is_valid, reason = validate_rfc_structure(f_bytes)
                if not is_valid:
                    errors.append(f"❌ **Blocked '{uf.name}'**: {reason}")
                    continue

                f_hash = hashlib.sha256(f_bytes).hexdigest()

                # 2. Duplicate Detection (Modified)
                cursor.execute("SELECT case_id FROM cases WHERE sha256 = ?", (f_hash,))
                existing = cursor.fetchone()
                
                if existing:
                    # Use the historical Case ID, but KEEP GOING so it loads into the session
                    case_id = existing["case_id"]
                else:
                    # Generate a new Case ID for new files
                    case_id = f"CASE-{hashlib.md5(f_bytes).hexdigest()[:6].upper()}"

                # 3. Pipeline Decomposition
                decomp = parse_step1_headers(f_bytes)
                sender = decomp["headers"].get("From", "Unknown")
                orig_ip = decomp["origin_candidate"].get("ip", "")
                subject = decomp["headers"].get("Subject", "(No Subject)")

                # Pass raw bytes so DKIM can verify cryptographic signatures
                auth = run_protocol_checks(sender, orig_ip, raw_bytes=f_bytes)
                decomp["hops"] = enrich_hop_chain(decomp["hops"])
                geo = get_ip_geolocation(orig_ip)
                # --- UPDATE THIS LINE ---
                heur = scan_body_heuristics(decomp.get("body_preview", ""), decomp.get("body_html", ""))

                # --- NEW: Run Ledger Cross-Reference ---
                intel = check_ledger_intelligence(sender, orig_ip, heur.get("urls", []))

                # 4. Risk Evaluation (Updated with Intel Penalty)
                risk = 10
                if auth.get("dkim", {}).get("status") in ["FAIL / MISSING", "ERROR"]: risk += 20
                if auth["spf"]["status"] == "FAIL": risk += 35
                if auth["dmarc"]["policy"] in ["NONE", "MISSING"]: risk += 10
                if geo.get("threat_score", 0) > 40: risk += 25
                risk += heur["score"]
                risk += intel["penalty"]  # <-- Add the new ledger penalty
                
                # --- NEW: Cap the absolute maximum risk score at 100 ---
                risk = min(risk, 100)
                # -------------------------------------------------------
                
                status_label = "🔴 Malicious" if risk >= 75 else ("🟡 Suspicious" if risk >= 45 else "🟢 Safe")


                # 5. Database Insertion OR Update
                # Package the full telemetry into a JSON string
                telemetry_package = {
                    "decomp": decomp, "auth": auth, "geo": geo, "heur": heur, "intel": intel
                }
                telemetry_str = json.dumps(telemetry_package)

                if not existing:
                    # New files get both timestamp and last_analyzed automatically set via SQLite defaults
                    cursor.execute("""
                        INSERT INTO cases (case_id, file_name, sha256, sender, subject, origin_ip, risk_score, status, telemetry)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (case_id, uf.name, f_hash, sender, subject, orig_ip, risk, status_label, telemetry_str))
                else:
                    # OVERWRITE the intelligence score and UPDATE last_analyzed, but PRESERVE original timestamp
                    cursor.execute("""
                        UPDATE cases 
                        SET risk_score = ?, status = ?, telemetry = ?, last_analyzed = CURRENT_TIMESTAMP
                        WHERE case_id = ?
                    """, (risk, status_label, telemetry_str, case_id))
                    
                # 6. Save into session memory for active workbench
                st.session_state.analyzed_store[case_id] = {
                    "case_id": case_id,
                    "file_name": uf.name, 
                    "hash": f_hash, 
                    "status": status_label,
                    "risk_score": risk,
                    "decomp": decomp, 
                    "auth": auth, 
                    "geo": geo, 
                    "heur": heur,
                    "intel": intel
                }
                success_cases.append(case_id)

            except Exception as e:
                errors.append(f"💥 **Fatal Error on '{uf.name}'**: {str(e)}")

        # Commit only validated cases
        conn.commit()
        conn.close()
        progress_bar.empty()

        # Display Errors (if any files were corrupt)
        if errors:
            for err in errors:
                st.markdown(err)

# Handle Successful Upload & Automatic Redirect
        if success_cases:
            st.session_state.selected_case = success_cases[-1]
            
            # Update the central state variable
            st.session_state.current_page = "🔬 Investigation Workbench"
            
            # Instantly trigger the page reload
            st.rerun()