import hashlib
import email
import streamlit as st
from logic.parser import parse_step1_headers
from logic.auth import run_protocol_checks
from logic.enrichment import get_ip_geolocation, enrich_hop_chain
from logic.heuristics import scan_body_heuristics
from logic.database import get_db_connection

def pre_flight_check(file_bytes: bytes) -> bool:
    """Validates that the uploaded file is a structurally sound RFC 822/MIME email."""
    try:
        msg = email.message_from_bytes(file_bytes)
        if not msg.keys():
            return False
        return True
    except Exception:
        return False

def render_upload():
    st.markdown("<h2>Forensic Ingestion Engine</h2>", unsafe_allow_html=True)
    st.caption("Strictly accepts .eml RFC 822 standard formats. Invalid payloads are rejected.")
    
    uploaded_files = st.file_uploader("Drop case files here", type=["eml"], accept_multiple_files=True)
    
    if st.button("🚀 Confirm & Process Batch", type="primary"):
        if uploaded_files:
            conn = get_db_connection()
            cursor = conn.cursor()
            success_count = 0
            error_log = []
            
            # 1. Initialize Progress Bar
            total_files = len(uploaded_files)
            progress_bar = st.progress(0, text="Initializing batch analysis...")

            for idx, uf in enumerate(uploaded_files):
                # 2. Update status text per file
                progress_bar.progress(idx / total_files, text=f"Analyzing {uf.name} ({idx+1}/{total_files})...")
                
                try:
                    # ---> [PASTE YOUR EXISTING PARSING, GEOIP, AND DB INSERT LOGIC HERE] <---
                    
                    success_count += 1
                except Exception as e:
                    # 3. Catch timeouts or corrupt files without crashing the app
                    error_log.append(f"❌ '{uf.name}' failed: {str(e)}")

            conn.commit()
            conn.close()
            
            # 4. Clear the bar and report results
            progress_bar.empty()
            
            if success_count > 0:
                st.success(f"Successfully processed and vaulted {success_count} case(s).")
            if error_log:
                for err in error_log:
                    st.error(err)
        else:
            st.warning("No files provided.")