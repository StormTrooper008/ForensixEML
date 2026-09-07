import streamlit as st

def render_settings():
    st.markdown("<h2>System Preferences</h2>", unsafe_allow_html=True)
    
    st.write(f"**Logged in as:** `{st.session_state.get('user', 'Unknown')}`")
    st.write("**Role:** Tier 2 Incident Responder")
    
    st.divider()
    
    st.subheader("🕰️ Timezone Configuration")
    tz_choice = st.selectbox(
        "Display Timestamps in:", 
        ["UTC (Forensic Standard)", "Local System Time"],
        index=0 if st.session_state.get("tz_pref", "UTC") == "UTC" else 1
    )
    
    # Instantly update session state when dropdown changes
    new_pref = "UTC" if tz_choice.startswith("UTC") else "Local"
    if new_pref != st.session_state.tz_pref:
        st.session_state.tz_pref = new_pref
        st.rerun()
    
    st.divider()
    st.info("💡 **Dark/Light Mode:** Click the three dots (⋮) in the top right corner of the screen, select 'Settings', and choose your preferred Theme.")
    st.divider()
    
    if st.button("🚪 Logout / End Session", type="primary"):
        st.session_state.logged_in = False
        st.session_state.user = None
        st.session_state.analyzed_store = {}
        st.rerun()