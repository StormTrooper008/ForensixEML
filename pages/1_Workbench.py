# pages/1_Workbench.py
import streamlit as st
from ui.workbench import render_workbench

# --- Page Configuration ---
st.set_page_config(
    page_title="Investigation Workbench", 
    page_icon="🔬", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply the same Dev Mode UI concealment here if active
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

# Security check: Ensure they are logged in via the main app first
if not st.session_state.get("logged_in", False):
    st.warning("🔒 Please log in through the main dashboard first.")
    st.page_link("app.py", label="Go to Login", icon="🏠")
else:
    # Render the workbench using your existing UI logic
    render_workbench()