import streamlit as st

def render_settings():
    st.markdown("<h2>System Preferences</h2>", unsafe_allow_html=True)
    
    st.write(f"**Logged in as:** `{st.session_state.get('user', 'Unknown')}`")
    st.write("**Role:** Tier 2 Incident Responder")
    
    st.divider()
    
    st.info("💡 **Dark/Light Mode:** Click the three dots (⋮) in the top right corner of the screen, select 'Settings', and choose your preferred Theme.")
    
    st.divider()
    
    if st.button("🚪 Logout / End Session", type="primary"):
        # Clear the session state completely
        st.session_state.logged_in = False
        st.session_state.user = None
        st.session_state.analyzed_store = {}
        st.rerun()