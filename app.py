# --- app.py ---
import streamlit as st

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

# Global Session State
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "analyzed_store" not in st.session_state:
    st.session_state.analyzed_store = {}
if "nav_page" not in st.session_state:
    st.session_state.nav_page = "🏠 Main Dashboard"
if "selected_case" not in st.session_state:
    st.session_state.selected_case = None

def login():
    st.markdown("<h2>Email Forensics Platform Login</h2>", unsafe_allow_html=True)
    with st.form("login_form"):
        username = st.text_input("Analyst ID")
        password = st.text_input("Passphrase", type="password")
        submit = st.form_submit_button("Authenticate")
        
        if submit and username == "admin" and password == "sih2026":
            st.session_state.logged_in = True
            st.session_state.user = username
            st.rerun()
        elif submit:
            st.error("Invalid credentials.")

if not st.session_state.logged_in:
    login()
else:
    nav_options = [
        "🏠 Main Dashboard", 
        "📂 Upload & Ingest", 
        "🔬 Investigation Workbench", 
        "🗄️ Database Ledger",
        "⚙️ Settings & User"
    ]

    with st.sidebar:
        st.markdown("## 💾 **Email Forensics**")
        st.divider()
        # Radio button controlled by session_state for dynamic redirecting
        page = st.radio(
            "Navigation Engine", 
            nav_options,
            index=nav_options.index(st.session_state.nav_page) if st.session_state.nav_page in nav_options else 0,
            key="sidebar_nav"
        )
        st.session_state.nav_page = page

    # Route according to active page
    if page == "🏠 Main Dashboard":
        render_dashboard()
    elif page == "📂 Upload & Ingest":
        render_upload()
    elif page == "🔬 Investigation Workbench":
        render_workbench()
    elif page == "🗄️ Database Ledger":
        render_ledger()
    elif page == "⚙️ Settings & User":
        render_settings()