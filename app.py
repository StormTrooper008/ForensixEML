import hashlib
import json
import email
import pandas as pd
import streamlit as st
import folium
from streamlit_folium import st_folium

# Forensic Modules
from logic.parser import parse_step1_headers
from logic.auth import run_protocol_checks
from logic.enrichment import get_ip_geolocation, enrich_hop_chain
from logic.heuristics import scan_body_heuristics
from logic.database import get_db_connection

# -----------------------------------------
# PAGE CONFIG & STYLING
# -----------------------------------------
st.set_page_config(page_title="Forensic Email Analyzer", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
        .metric-card { background-color: #1e293b; color: white; border-radius: 10px; padding: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .hero-banner { background: linear-gradient(135deg, #0f172a, #1e3a8a); padding: 25px; border-radius: 12px; color: white; margin-bottom: 20px; }
    </style>
""", unsafe_allow_html=True)

# -----------------------------------------
# AUTHENTICATION & SESSION STATE
# -----------------------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "analyzed_store" not in st.session_state:
    st.session_state.analyzed_store = {}

def login():
    """Simple hardcoded auth for the MVP. Will be moved to the DB users table later."""
    st.markdown("<div class='hero-banner'><h2>🛡️ Sentinel Platform Login</h2><p>Restricted Forensic Appliance</p></div>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        with st.form("login_form"):
            username = st.text_input("Analyst ID")
            password = st.text_input("Passphrase", type="password")
            submit = st.form_submit_button("Authenticate", use_container_width=True)
            
            if submit:
                # Default MVP Credentials
                if username == "admin" and password == "sih2026":
                    st.session_state.logged_in = True
                    st.session_state.user = username
                    st.rerun()
                else:
                    st.error("Invalid credentials. Access Denied.")

def logout():
    st.session_state.logged_in = False
    st.session_state.analyzed_store = {}
    st.rerun()

# -----------------------------------------
# PRE-FLIGHT SANDBOX
# -----------------------------------------
def pre_flight_check(file_bytes: bytes) -> bool:
    """Validates that the uploaded file is a structurally sound RFC 822/MIME email."""
    try:
        msg = email.message_from_bytes(file_bytes)
        # A valid email must have at least some basic headers
        if not msg.keys():
            return False
        return True
    except Exception:
        return False

# -----------------------------------------
# MAIN APPLICATION ROUTER
# -----------------------------------------
if not st.session_state.logged_in:
    login()
else:
    # --- SIDEBAR NAV ---
    with st.sidebar:
        st.markdown("## 🛡️ **Forensic Appliance**")
        st.caption("Active Session: Tier 2 Analyst")
        st.divider()
        page = st.radio("Navigation Engine", [
            "🏠 Main Dashboard", 
            "📂 Upload & Ingest", 
            "🔬 Investigation Workbench", 
            "🗄️ Database Ledger",
            "⚙️ Settings & User"
        ])
        st.divider()
        st.caption("Dark/Light Mode: Use top right settings menu ⋮")

    # --- PAGE 1: MAIN DASHBOARD ---
    if page == "🏠 Main Dashboard":
        st.markdown("<div class='hero-banner'><h2>System Overview</h2><p>Active organizational threats and parsed email telemetry</p></div>", unsafe_allow_html=True)
        
        conn = get_db_connection()
        cases_df = pd.read_sql_query("SELECT * FROM cases ORDER BY timestamp DESC", conn)
        conn.close()

        total = len(cases_df)
        high_risk = len(cases_df[cases_df['risk_score'] >= 75]) if total > 0 else 0
        
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Ingested Cases", total)
        c2.metric("Critical Threats Detected", high_risk)
        c3.metric("System Status", "Online & Secure")

        st.subheader("Recent Threat Activity")
        if total > 0:
            st.dataframe(cases_df.head(10), use_container_width=True, hide_index=True)
        else:
            st.info("No cases ingested yet. Proceed to Upload & Ingest.")

    # --- PAGE 2: UPLOAD & INGEST ---
    elif page == "📂 Upload & Ingest":
        st.markdown("<div class='hero-banner'><h2>Forensic Ingestion Engine</h2><p>Strictly accepts .eml RFC 822 standard formats.</p></div>", unsafe_allow_html=True)
        
        uploaded_files = st.file_uploader("Drop case files here", type=["eml"], accept_multiple_files=True)
        if st.button("🚀 Confirm & Process Batch", type="primary"):
            if uploaded_files:
                conn = get_db_connection()
                cursor = conn.cursor()
                success_count = 0
                
                for uf in uploaded_files:
                    f_bytes = uf.read()
                    f_hash = hashlib.sha256(f_bytes).hexdigest()

                    # Pre-flight Check
                    if not pre_flight_check(f_bytes):
                        st.error(f"Sandbox blocked '{uf.name}': Not a valid RFC 822 email file.")
                        continue

                    # Prevent Duplicates
                    cursor.execute("SELECT case_id FROM cases WHERE sha256 = ?", (f_hash,))
                    if cursor.fetchone():
                        st.warning(f"File '{uf.name}' already exists in database.")
                        continue

                    # Parsing Pipeline
                    case_id = f"CASE-{hashlib.md5(f_bytes).hexdigest()[:6].upper()}"
                    decomp = parse_step1_headers(f_bytes)
                    sender = decomp["headers"]["From"]
                    orig_ip = decomp["origin_candidate"]["ip"]
                    
                    auth = run_protocol_checks(sender, orig_ip)
                    decomp["hops"] = enrich_hop_chain(decomp["hops"])
                    geo = get_ip_geolocation(orig_ip)
                    heur = scan_body_heuristics(decomp["body_preview"])

                    # Risk Scoring
                    risk = 10
                    if auth["spf"]["status"] == "FAIL": risk += 35
                    if auth["dmarc"]["policy"] in ["NONE", "MISSING"]: risk += 10
                    if geo.get("threat_score", 0) > 40: risk += 25
                    risk += heur["score"]
                    status = "🔴 Malicious" if risk >= 75 else ("🟡 Suspicious" if risk >= 45 else "🟢 Safe")

                    # Save to Database
                    cursor.execute("""
                        INSERT INTO cases (case_id, file_name, sha256, sender, subject, origin_ip, risk_score, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (case_id, uf.name, f_hash, sender, decomp["headers"]["Subject"], orig_ip, risk, status))
                    
                    # Keep detailed JSON in active session memory for the Workbench
                    st.session_state.analyzed_store[case_id] = {
                        "file_name": uf.name, "hash": f_hash, "decomp": decomp, "auth": auth, "geo": geo, "heur": heur
                    }
                    success_count += 1

                conn.commit()
                conn.close()
                if success_count > 0:
                    st.success(f"Successfully processed and vaulted {success_count} case(s).")
            else:
                st.warning("No files provided.")

    # --- PAGE 3: INVESTIGATION WORKBENCH ---
    elif page == "🔬 Investigation Workbench":
        st.markdown("<div class='hero-banner'><h2>Active Evidence Workbench</h2><p>Deep-dive telemetry for current session memory.</p></div>", unsafe_allow_html=True)
        
        if not st.session_state.analyzed_store:
            st.info("No active cases in session. Please upload a file first.")
        else:
            selected_case = st.selectbox("Select Active Case:", list(st.session_state.analyzed_store.keys()))
            data = st.session_state.analyzed_store[selected_case]
            
            st.write(f"**Investigating:** `{data['file_name']}` | **SHA256:** `{data['hash']}`")
            
            t1, t2, t3, t4 = st.tabs(["Headers & Body", "Authentication", "Geo Map", "Heuristics"])
            
            with t1:
                st.json(data["decomp"]["headers"])
                st.text_area("Body Preview", data["decomp"]["body_preview"], height=150)
            with t2:
                st.json(data["auth"])
            with t3:
                st.write(f"**Origin IP:** {data['geo'].get('ip')} | **Country:** {data['geo'].get('country')}")
                if data["geo"].get("lat") and data["geo"].get("lon"):
                    m = folium.Map(location=[data["geo"]["lat"], data["geo"]["lon"]], zoom_start=3)
                    folium.Marker([data["geo"]["lat"], data["geo"]["lon"]], popup=data["geo"].get("ip")).add_to(m)
                    st_folium(m, width=700, height=350)
            with t4:
                st.metric("Heuristic Risk Penalty", data["heur"]["score"])
                st.write("**Extracted URLs:**", data["heur"]["urls"])
                st.write("**Trigger Keywords:**", data["heur"]["keywords"])

    # --- PAGE 4: DATABASE LEDGER ---
    elif page == "🗄️ Database Ledger":
        st.markdown("<div class='hero-banner'><h2>Organizational Ledger</h2><p>Access historical cases, internal users, and blocklists.</p></div>", unsafe_allow_html=True)
        
        conn = get_db_connection()
        tab_cases, tab_emps, tab_blocks = st.tabs(["Cases Vault", "Employee Roster", "Blocklist Indicators"])
        
        with tab_cases:
            df_cases = pd.read_sql_query("SELECT * FROM cases", conn)
            st.dataframe(df_cases, use_container_width=True)
        with tab_emps:
            df_emps = pd.read_sql_query("SELECT * FROM employees", conn)
            st.dataframe(df_emps, use_container_width=True)
        with tab_blocks:
            df_blocks = pd.read_sql_query("SELECT * FROM blocklist", conn)
            st.dataframe(df_blocks, use_container_width=True)
        conn.close()

    # --- PAGE 5: SETTINGS ---
    elif page == "⚙️ Settings & User":
        st.markdown("<div class='hero-banner'><h2>System Preferences</h2></div>", unsafe_allow_html=True)
        st.write(f"**Logged in as:** `{st.session_state.user}`")
        st.info("💡 **Dark/Light Mode:** Click the three dots (⋮) in the top right corner of the screen, select 'Settings', and choose your preferred Theme.")
        if st.button("🚪 Logout / End Session", type="primary"):
            logout()