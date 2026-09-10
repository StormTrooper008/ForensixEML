# app.py
import streamlit as st

from ui.correlation import render_correlation_view
from ui.login import render_login
from ui.dashboard import render_dashboard
from ui.upload import render_upload
from ui.workbench import render_workbench
from ui.ledger import render_ledger
from ui.settings import render_settings

st.set_page_config(
    page_title="Email Forensics Platform", 
    page_icon="💾", 
    layout="wide", 
    initial_sidebar_state="expanded"
)

st.markdown("""
    <style>
        .hero-banner { background: #1e3a8a; padding: 25px; border-radius: 12px; color: white; margin-bottom: 20px; }
        .metric-card { background-color: #1e293b; color: #f8fafc; border-radius: 10px; padding: 20px; border: 1px solid #334155; }
        div[data-testid="stMetricValue"] { color: #f8fafc; }
    </style>
""", unsafe_allow_html=True)

# --- Global Session State ---
if "logged_in" not in st.session_state: st.session_state.logged_in = False
if "user_role" not in st.session_state: st.session_state.user_role = None
if "analyzed_store" not in st.session_state: st.session_state.analyzed_store = {}
if "current_page" not in st.session_state: st.session_state.current_page = "🏠 Main Dashboard"
if "selected_case" not in st.session_state: st.session_state.selected_case = None
if "tz_pref" not in st.session_state: st.session_state.tz_pref = "UTC"

# --- GLOBAL UI CONCEALMENT (Safe Mode) ---
if st.session_state.get("dev_mode", False):
    st.markdown("""
        <style>
            [data-testid="stToolbar"] {visibility: hidden !important;}
            #MainMenu {visibility: hidden !important;}
            [data-testid="collapsedControl"] {
                visibility: visible !important;
                z-index: 9999 !important;
            }
        </style>
    """, unsafe_allow_html=True)

# --- GLOBAL HUD (Heads-Up Display) ---
if st.session_state.logged_in:
    hud_container = st.container()
    with hud_container:
        if st.session_state.get("auto_ingest", False):
            st.info("🟢 **SYSTEM STATUS:** Auto-Ingestion Daemon is **ACTIVE** in the background.")
        else:
            st.warning("⏸️ **SYSTEM STATUS:** Auto-Ingestion Daemon is **PAUSED**. Enable in Settings.")

# --- Routing Engine ---
if not st.session_state.logged_in:
    render_login()
else:
    nav_options = [
        "🏠 Main Dashboard", 
        "📂 Upload & Ingest", 
        "🔬 Investigation Workbench", 
        "🕸️ Threat Graph & Campaigns",
        "🗄️ Database Ledger",
        "⚙️ Settings & User"
    ]

    with st.sidebar:
        st.markdown("<h2>💾 Email Forensics</h2>", unsafe_allow_html=True)
        st.caption(f"Logged in as: `{st.session_state.get('user', 'Unknown')}` ({st.session_state.user_role})")
        st.divider()
        st.markdown("### 🧭 Navigation")
        
        if st.session_state.current_page not in nav_options:
            st.session_state.current_page = nav_options[0]

        for page in nav_options:
            is_active = (st.session_state.current_page == page)
            if st.button(page, type="primary" if is_active else "secondary", use_container_width=True):
                st.session_state.current_page = page
                st.rerun()

    # --- Page Render Execution ---
    if st.session_state.current_page == "🏠 Main Dashboard":
        render_dashboard()
    elif st.session_state.current_page == "📂 Upload & Ingest":
        render_upload()
    elif st.session_state.current_page == "🔬 Investigation Workbench":
        render_workbench()
    elif st.session_state.current_page == "🕸️ Threat Graph & Campaigns":
        render_correlation_view()
    elif st.session_state.current_page == "🗄️ Database Ledger":
        render_ledger()
    elif st.session_state.current_page == "⚙️ Settings & User":
        render_settings()