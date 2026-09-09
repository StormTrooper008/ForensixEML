# --- ui/login.py ---
import streamlit as st

def render_login():
    """Renders the authentication portal and sets RBAC session parameters."""
    st.markdown("<h2>Vipatra Cyber Forensics | Gateway</h2>", unsafe_allow_html=True)
    st.caption("Institutional & Enterprise Access Portal")

    col1, col2 = st.columns([1.5, 1])

    with col1:
        with st.form("login_form"):
            user_input = st.text_input("Corporate ID / University Email")
            pass_input = st.text_input("Passphrase", type="password")
            submit = st.form_submit_button("Authenticate", use_container_width=True)

            if submit:
                # 1. Analyst / Admin Credential Check
                if user_input.strip() == "admin" and pass_input == "sih2026":
                    st.session_state.logged_in = True
                    st.session_state.user = "Lead Forensic Analyst"
                    st.session_state.user_role = "Analyst"
                    st.rerun()

                # 2. Scoped Employee / Student Credential Check
                elif user_input.strip() == "employee" and pass_input == "test":
                    st.session_state.logged_in = True
                    st.session_state.user = "General Personnel / Campus User"
                    st.session_state.user_role = "Employee"
                    st.rerun()

                else:
                    st.error("Authentication failed: Invalid credentials.")

    with col2:
        st.info(
            "**Access Levels:**\n\n"
            "- **Analyst:** Access to deep MIME decomposition, cryptographic verification, "
            "GeoIP reverse hop routing, and database ledgers.\n\n"
            "- **Employee / Personnel:** Read-only portal with user-level containment directives "
            "and triage reporting."
        )