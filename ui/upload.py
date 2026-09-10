# --- ui/upload.py ---
import os
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
from logic.classifier import run_local_classifier

SPOOL_DIR = "inbox_spool"
os.makedirs(SPOOL_DIR, exist_ok=True)

def validate_rfc_structure(file_bytes: bytes) -> tuple[bool, str]:
    if not file_bytes or len(file_bytes.strip()) == 0:
        return False, "File is completely empty (0 bytes)."
    try:
        msg = email.message_from_bytes(file_bytes, policy=policy.default)
    except Exception as e:
        return False, f"MIME parser crash: {str(e)}"

    from_header = msg.get("From", "")
    if not from_header:
        return False, "Corrupted EML: Missing mandatory 'From' header."
    if "@" not in from_header or not re.search(r"[\w.-]+@[\w.-]+", from_header):
        return False, f"Corrupted EML: 'From' header contains no valid email address."

    rfc_markers = ["Date", "Subject", "Message-ID", "Received"]
    if not [m for m in rfc_markers if msg.get(m)]:
        return False, "Corrupted EML: Lacks standard RFC routing headers."
    return True, "Valid"

def process_raw_eml_bytes(file_name: str, f_bytes: bytes) -> tuple[bool, str, dict]:
    f_hash = hashlib.sha256(f_bytes).hexdigest()

    # --- MICRO-TRANSACTION 1: Read-Only Checks ---
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM rejected_files WHERE sha256 = ?", (f_hash,))
    if cursor.fetchone():
        conn.close()
        return False, "DUPLICATE_REJECTED", {"error": "Already in Rejected Ledger."}

    is_valid, reason = validate_rfc_structure(f_bytes)
    if not is_valid:
        cursor.execute("INSERT INTO rejected_files (file_name, sha256, rejection_reason) VALUES (?, ?, ?)", (file_name, f_hash, reason))
        conn.commit()
        conn.close()
        return False, "INVALID_RFC", {"error": reason}

    cursor.execute("SELECT case_id FROM cases WHERE sha256 = ?", (f_hash,))
    existing = cursor.fetchone()
    case_id = existing["case_id"] if existing else f"CASE-{hashlib.md5(f_bytes).hexdigest()[:6].upper()}"
    
    # CRITICAL: Close the database completely before starting AI tasks
    conn.close() 

    # --- HEAVY AI INFERENCE (Database is safely closed) ---
    decomp = parse_step1_headers(f_bytes)
    sender = decomp["headers"].get("From", "Unknown")
    orig_ip = decomp["origin_candidate"].get("ip", "")
    subject = decomp["headers"].get("Subject", "(No Subject)")

    auth = run_protocol_checks(sender, orig_ip, raw_bytes=f_bytes)
    decomp["hops"] = enrich_hop_chain(decomp["hops"])
    geo = get_ip_geolocation(orig_ip)
    heur = scan_body_heuristics(decomp.get("body_preview", ""), decomp.get("body_html", ""))
    intel = check_ledger_intelligence(sender, orig_ip, heur.get("urls", []))

    risk = 10
    if auth.get("dkim", {}).get("status") in ["FAIL / MISSING", "ERROR"]: risk += 20
    if auth["spf"]["status"] == "FAIL": risk += 35
    if auth["dmarc"]["policy"] in ["NONE", "MISSING"]: risk += 10
    if geo.get("threat_score", 0) > 40: risk += 25
    if decomp.get("has_risky_attachments"): risk += 50
    risk += heur["score"]
    risk += intel["penalty"]
    risk = min(risk, 100)

    email_full_text = decomp.get("body_full", "") + " " + decomp["headers"].get("Subject", "")
    local_ai_result = run_local_classifier(email_full_text)
    local_score = local_ai_result.get("phishing_probability", risk)
    final_risk = int((risk + local_score) / 2)

    telemetry_package = {
        "decomp": decomp, "auth": auth, "geo": geo, "heur": heur, 
        "intel": intel, "risk_score": final_risk, "local_ai": local_ai_result
    }

    if final_risk >= 40:
        ai_results = generate_incident_summary(telemetry_package)
        ai_summary_text = ai_results.get("ai_summary", "No summary generated.")
    else:
        ai_summary_text = "🟢 [Automated Clearance] Baseline heuristics and DistilBERT scored this email as benign."

    status_label = "🔴 Malicious" if final_risk >= 75 else ("🟡 Suspicious" if final_risk >= 45 else "🟢 Safe")
    telemetry_package["ai_insight"] = ai_summary_text
    telemetry_str = json.dumps(telemetry_package)
    ai_notes_text = ai_summary_text

    # --- MICRO-TRANSACTION 2: Write Results ---
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if not existing:
        cursor.execute("""
            INSERT INTO cases (case_id, file_name, sha256, sender, subject, origin_ip, risk_score, status, telemetry, ai_notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (case_id, file_name, f_hash, sender, subject, orig_ip, final_risk, status_label, telemetry_str, ai_notes_text))
    else:
        cursor.execute("""
            UPDATE cases 
            SET risk_score = ?, status = ?, telemetry = ?, ai_notes = ?, last_analyzed = CURRENT_TIMESTAMP
            WHERE case_id = ?
        """, (final_risk, status_label, telemetry_str, ai_notes_text, case_id))

    conn.commit()
    conn.close()

    return True, case_id, {
        "case_id": case_id, "file_name": file_name, "hash": f_hash,
        "status": status_label, "risk_score": final_risk, "decomp": decomp,
        "auth": auth, "geo": geo, "heur": heur, "intel": intel,
        "ai_insight": ai_summary_text
    }

@st.dialog("⚠️ Ingestion Failures Detected")
def show_error_popup(errors_list):
    st.error("Some files were rejected by the strict RFC validation engine.")
    for err in errors_list:
        st.write(f"- {err}")
    if st.button("Acknowledge"):
        st.rerun()

def render_upload():
    st.markdown("<h2>Forensic Ingestion Engine</h2>", unsafe_allow_html=True)
    st.caption("RFC 5322 Ingestion Pipeline supporting ad-hoc investigations and live monitoring.")

    tab_manual, tab_live = st.tabs(["📤 Ad-Hoc Manual Upload", "📡 Live Spool Viewer"])

    with tab_manual:
        st.write("Upload specific `.eml` files flagged by employees or external alerts for immediate triage.")
        uploaded_files = st.file_uploader("Drop investigative case files here", type=["eml"], accept_multiple_files=True, key="manual_uploader")
        
        if st.button("🚀 Confirm & Process Batch", type="primary", key="btn_manual_process"):
            if not uploaded_files:
                st.warning("No files provided.")
                return

            total_files = len(uploaded_files)
            progress_bar = st.progress(0, text="Initializing ingestion sandbox...")
            success_cases, errors = [], []

            for idx, uf in enumerate(uploaded_files):
                progress_bar.progress((idx) / total_files, text=f"Inspecting '{uf.name}' ({idx + 1}/{total_files})...")
                try:
                    f_bytes = uf.read()
                    # The function now handles its own database connection seamlessly
                    ok, cid_or_reason, data = process_raw_eml_bytes(uf.name, f_bytes)
                    if ok:
                        st.session_state.analyzed_store[cid_or_reason] = data
                        success_cases.append(cid_or_reason)
                    else:
                        errors.append(f"❌ **Blocked '{uf.name}'**: {data.get('error', cid_or_reason)}")
                except Exception as e:
                    errors.append(f"💥 **Fatal Error on '{uf.name}'**: {str(e)}")

            progress_bar.empty()

            if success_cases:
                st.session_state.selected_case = success_cases[-1]
                st.session_state.current_page = "🔬 Investigation Workbench"

            if errors:
                show_error_popup(errors)
            elif success_cases:
                st.rerun()

    with tab_live:
        st.write("Monitor raw `.eml` files generated by the simulator before they are processed.")
        
        pending_files = [f for f in os.listdir(SPOOL_DIR) if f.endswith(".eml")]
        st.metric("Files Awaiting Ingestion", len(pending_files))
        
        if pending_files:
            for fname in pending_files:
                with st.expander(f"📄 {fname}"):
                    fpath = os.path.join(SPOOL_DIR, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            st.code(f.read(), language="email")
                    except Exception as e:
                        st.error(f"Cannot read file: {e}")
        else:
            if st.session_state.get("auto_ingest", False):
                st.success("✅ Spool is clean. The Auto-Ingestion Daemon is actively processing incoming traffic.")
            else:
                st.info("Spool is currently empty. Run `traffic_simulator.py` to generate test cases.")