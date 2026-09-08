# --- ui/upload.py ---
import hashlib
import re
import streamlit as st
import json
import email
from email import policy

from logic.ai_agent import generate_incident_summary
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


@st.dialog("⚠️ Ingestion Failures Detected")
def show_error_popup(errors_list):
    st.error("Some files were rejected by the strict RFC validation engine.")
    for err in errors_list:
        st.write(f"- {err}")
    st.info("Full details have been recorded in the Rejected Files Ledger.")
    # When acknowledged, it will reload the page (and navigate to workbench if valid files existed)
    if st.button("Acknowledge"):
        st.rerun()


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
                f_hash = hashlib.sha256(f_bytes).hexdigest()
                
                # 1. Check if already rejected
                cursor.execute("SELECT id FROM rejected_files WHERE sha256 = ?", (f_hash,))
                if cursor.fetchone():
                    errors.append(f"❌ **Blocked '{uf.name}'**: Duplicate (Already in Rejected Ledger).")
                    continue
                
                # 2. Strict Sandbox Validation
                is_valid, reason = validate_rfc_structure(f_bytes)
                if not is_valid:
                    cursor.execute("INSERT INTO rejected_files (file_name, sha256, rejection_reason) VALUES (?, ?, ?)", (uf.name, f_hash, reason))
                    errors.append(f"❌ **Blocked '{uf.name}'**: {reason}")
                    continue

                # 2. Duplicate Detection
                cursor.execute("SELECT case_id FROM cases WHERE sha256 = ?", (f_hash,))
                existing = cursor.fetchone()
                
                if existing:
                    case_id = existing["case_id"]
                else:
                    case_id = f"CASE-{hashlib.md5(f_bytes).hexdigest()[:6].upper()}"

                # 3. Pipeline Decomposition
                decomp = parse_step1_headers(f_bytes)
                sender = decomp["headers"].get("From", "Unknown")
                orig_ip = decomp["origin_candidate"].get("ip", "")
                subject = decomp["headers"].get("Subject", "(No Subject)")

                auth = run_protocol_checks(sender, orig_ip, raw_bytes=f_bytes)
                decomp["hops"] = enrich_hop_chain(decomp["hops"])
                geo = get_ip_geolocation(orig_ip)
                heur = scan_body_heuristics(decomp.get("body_preview", ""), decomp.get("body_html", ""))
                intel = check_ledger_intelligence(sender, orig_ip, heur.get("urls", []))

                # 4. Baseline Risk Evaluation 
                risk = 10
                if auth.get("dkim", {}).get("status") in ["FAIL / MISSING", "ERROR"]: risk += 20
                if auth["spf"]["status"] == "FAIL": risk += 35
                if auth["dmarc"]["policy"] in ["NONE", "MISSING"]: risk += 10
                if geo.get("threat_score", 0) > 40: risk += 25
                risk += heur["score"]
                risk += intel["penalty"]
                risk = min(risk, 100)

                # 5. AI Threat Synthesis
                telemetry_package = {
                    "decomp": decomp, "auth": auth, "geo": geo, "heur": heur, "intel": intel, "risk_score": risk
                }
                
                api_key = st.session_state.get("gemini_api_key", "")
                ai_results = generate_incident_summary(telemetry_package, api_key)
                
                final_risk = ai_results.get("ai_score", risk)
                status_label = "🔴 Malicious" if final_risk >= 75 else ("🟡 Suspicious" if final_risk >= 45 else "🟢 Safe")

                telemetry_package["ai_insight"] = ai_results.get("ai_summary", "No summary generated.")
                telemetry_str = json.dumps(telemetry_package)

                # 6. Database Insertion OR Update
                if not existing:
                    cursor.execute("""
                        INSERT INTO cases (case_id, file_name, sha256, sender, subject, origin_ip, risk_score, status, telemetry)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (case_id, uf.name, f_hash, sender, subject, orig_ip, final_risk, status_label, telemetry_str))
                else:
                    cursor.execute("""
                        UPDATE cases 
                        SET risk_score = ?, status = ?, telemetry = ?, last_analyzed = CURRENT_TIMESTAMP
                        WHERE case_id = ?
                    """, (final_risk, status_label, telemetry_str, case_id))
                    
                # 7. Save into session memory
                st.session_state.analyzed_store[case_id] = {
                    "case_id": case_id,
                    "file_name": uf.name, 
                    "hash": f_hash, 
                    "status": status_label,
                    "risk_score": final_risk,
                    "decomp": decomp, 
                    "auth": auth, 
                    "geo": geo, 
                    "heur": heur,
                    "intel": intel,
                    "ai_insight": telemetry_package["ai_insight"] 
                }
                success_cases.append(case_id)

            except Exception as e:
                # Also log fatal processing errors to the ledger
                cursor.execute("INSERT INTO rejected_files (file_name, rejection_reason) VALUES (?, ?)", (uf.name, f"Fatal Processing Error: {str(e)}"))
                errors.append(f"💥 **Fatal Error on '{uf.name}'**: {str(e)}")

        # Commit everything to database
        conn.commit()
        conn.close()
        progress_bar.empty()

        # --- FIX: Proper Redirect and Popup Handling ---
        # If there are successes, queue the redirect in session state first
        if success_cases:
            st.session_state.selected_case = success_cases[-1]
            st.session_state.current_page = "🔬 Investigation Workbench"

        # If there are errors, show the blocking modal. (When they click acknowledge, it will rerun and follow the redirect).
        if errors:
            show_error_popup(errors)
        # If no errors but there are successes, redirect instantly.
        elif success_cases:
            st.rerun()