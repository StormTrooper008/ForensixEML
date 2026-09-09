# app.py
import streamlit as st

from ui.login import render_login
from ui.dashboard import render_dashboard
from ui.upload import render_upload
from ui.workbench import render_workbench
from ui.ledger import render_ledger
from ui.settings import render_settings

st.set_page_config(page_title="Email Forensics Platform", page_icon="💾", layout="wide")

st.markdown("""
    <style>
        .hero-banner { background: #1e3a8a; padding: 25px; border-radius: 12px; color: white; margin-bottom: 20px; }
        .metric-card { background-color: #1e293b; color: #f8fafc; border-radius: 10px; padding: 20px; border: 1px solid #334155; }
        div[data-testid="stMetricValue"] { color: #f8fafc; }
    </style>
""", unsafe_allow_html=True)

# --- Global Session State ---
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user_role" not in st.session_state:
    st.session_state.user_role = None
if "analyzed_store" not in st.session_state:
    st.session_state.analyzed_store = {}
if "current_page" not in st.session_state:
    st.session_state.current_page = "🏠 Main Dashboard"
if "selected_case" not in st.session_state:
    st.session_state.selected_case = None
if "tz_pref" not in st.session_state:
    st.session_state.tz_pref = "UTC"

# --- GLOBAL UI CONCEALMENT ---
if not st.session_state.get("dev_mode", False):
    st.markdown("""
        <style>
            #MainMenu {visibility: hidden;}
            [data-testid="stToolbar"] {visibility: hidden;}
        </style>
    """, unsafe_allow_html=True)

# --- Routing Engine ---
if not st.session_state.logged_in:
    render_login()
else:
    if st.session_state.user_role == "Analyst":
        nav_options = [
            "🏠 Main Dashboard", 
            "📂 Upload & Ingest", 
            "🔬 Investigation Workbench", 
            "🗄️ Database Ledger",
            "⚙️ Settings & User"
        ]
    else:
        # Scoped Employee Portal View
        nav_options = [
            "🏠 Main Dashboard",
            "⚙️ Settings & User"
        ]

    with st.sidebar:
        st.markdown(f"## 💾 **Email Forensics**")
        st.caption(f"Logged in as: `{st.session_state.get('user', 'Unknown')}` ({st.session_state.user_role})")
        if st.button("🚪 Log Out"):
            st.session_state.logged_in = False
            st.session_state.user_role = None
            st.session_state.user = None
            st.rerun()
        st.divider()
        
        if st.session_state.current_page not in nav_options:
            st.session_state.current_page = nav_options[0]

        active_index = nav_options.index(st.session_state.current_page)
        
        selected_page = st.radio(
            "Navigation Engine", 
            nav_options,
            index=active_index
        )
        st.session_state.current_page = selected_page

    # Route according to active page
    if st.session_state.current_page == "🏠 Main Dashboard":
        render_dashboard()
    elif st.session_state.current_page == "📂 Upload & Ingest":
        render_upload()
    elif st.session_state.current_page == "🔬 Investigation Workbench":
        render_workbench()
    elif st.session_state.current_page == "🗄️ Database Ledger":
        render_ledger()
    elif st.session_state.current_page == "⚙️ Settings & User":
        render_settings()