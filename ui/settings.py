import streamlit as st
from logic.database import get_db_connection

def render_settings():
    st.markdown("<h2>System Preferences</h2>", unsafe_allow_html=True)
    
    st.write(f"**Logged in as:** `{st.session_state.get('user', 'Unknown')}`")
    st.write("**Role:** Tier 2 Incident Responder")
    
    st.divider()
    
    # --- TIMEZONE CONFIGURATION ---
    st.subheader("🕰️ Timezone Configuration")
    tz_choice = st.selectbox(
        "Display Timestamps in:", 
        ["UTC (Forensic Standard)", "Local System Time"],
        index=0 if st.session_state.get("tz_pref", "UTC") == "UTC" else 1
    )
    
    new_pref = "UTC" if tz_choice.startswith("UTC") else "Local"
    if new_pref != st.session_state.get("tz_pref"):
        st.session_state.tz_pref = new_pref
        st.rerun()
    
    st.divider()
    
    # --- AI ENGINE CONFIGURATION ---
    st.subheader("🧠 AI Threat Synthesis")
    st.caption("Enter your Gemini API key to enable automated incident reporting.")
    api_key_input = st.text_input("Gemini API Key", value=st.session_state.get("gemini_api_key", ""), type="password")
    if api_key_input != st.session_state.get("gemini_api_key"):
        st.session_state.gemini_api_key = api_key_input
        st.rerun()

    st.divider()
    
    # --- NATIVE THEME INSTRUCTIONS ---
    st.subheader("🎨 Interface Theme")
    st.info("""
        **To change the theme natively:**
        1. Enable Dev Mode below to reveal the top-right menu (⋮).
        2. Click the menu and select **Settings**.
        3. Change the **Theme** to Light or Dark. 
        *(Note: Streamlit prevents programmatic theme switching for security/rendering reasons).*
    """)
        
    st.divider()
    
    # --- DEV MODE & PURGE LOGIC ---
    st.subheader("🛠️ Developer & Diagnostics")
    dev_mode_current = st.session_state.get("dev_mode", False)
    
    dev_toggle = st.checkbox("Enable Developer Mode (Exposes system menus & test tools)", value=dev_mode_current)
    
    if dev_toggle != dev_mode_current:
        if dev_toggle:
            st.warning("⚠️ **Warning:** Enabling Dev Mode exposes backend controls. Proceed?")
            if st.button("Confirm Enable Dev Mode"):
                st.session_state.dev_mode = True
                st.rerun()
        else:
            st.session_state.dev_mode = False
            try:
                conn = get_db_connection()
                conn.execute("DELETE FROM crash_logs WHERE user = 'Dev_Testing' OR error_message LIKE '%Simulated%'")
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"Purge failed: {e}")
            st.rerun()
    
    st.divider()
    
    if st.button("🚪 Logout / End Session", type="primary"):
        st.session_state.logged_in = False
        st.session_state.user = None
        st.session_state.analyzed_store = {}
        st.rerun()