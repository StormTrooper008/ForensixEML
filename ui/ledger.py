import streamlit as st
from logic.database import get_db_connection

from ui.ledger_modules.tab_vault import render_tab_vault
from ui.ledger_modules.tab_personnel import render_tab_personnel
from ui.ledger_modules.tab_blocklist import render_tab_blocklist
from ui.ledger_modules.tab_manage import render_tab_manage
from ui.ledger_modules.tab_diagnostics import render_tab_diagnostics

def render_ledger():
    if "ledger_subview" not in st.session_state:
        st.session_state.ledger_subview = "menu"

    conn = get_db_connection()

    if st.session_state.ledger_subview != "menu":
        # --- GLOBAL SUBVIEW HEADER ---
        nav_col1, nav_col2 = st.columns([5, 1])
        with nav_col1:
            if st.button("⬅️ Back to Ledger Menu", type="secondary"):
                st.session_state.ledger_subview = "menu"
                st.rerun()
        with nav_col2:
            if st.button("🔄 Refresh Data", type="primary", use_container_width=True, key="refresh_module"):
                st.rerun()
                
        st.divider()

        # Render the selected module below the global header
        if st.session_state.ledger_subview == "vault":
            render_tab_vault(conn)
        elif st.session_state.ledger_subview == "personnel":
            render_tab_personnel(conn)
        elif st.session_state.ledger_subview == "blocklist":
            render_tab_blocklist(conn)
        elif st.session_state.ledger_subview == "diagnostics":
            render_tab_diagnostics(conn)
        elif st.session_state.ledger_subview == "manage":
            render_tab_manage(conn)

    else:
        # --- MAIN LEDGER MENU HUB ---
        menu_col1, menu_col2 = st.columns([5, 1])
        with menu_col1:
            st.markdown("<h2>Organizational Ledger Hub</h2>", unsafe_allow_html=True)
            st.markdown("Select a database module below to inspect records, filter data, or execute management tasks.")
        with menu_col2:
            st.write("")
            if st.button("🔄 Refresh Data", use_container_width=True, key="refresh_hub"):
                st.rerun()
                
        st.write("")

        # Row 1
        r1_c1, r1_c2 = st.columns(2, gap="large")
        with r1_c1:
            st.markdown("### 🗄️ Cases Vault")
            st.markdown("Inspect historical investigation reports, threat metrics, and load past cases into the workbench.")
            if st.button("Open Cases Vault", use_container_width=True, type="primary"):
                st.session_state.ledger_subview = "vault"
                st.rerun()

        with r1_c2:
            st.markdown("### 👥 Personnel Roster")
            st.markdown("Manage institutional personnel, student/staff rosters, organization IDs, and official emails.")
            if st.button("Open Personnel Roster", use_container_width=True, type="primary"):
                st.session_state.ledger_subview = "personnel"
                st.rerun()

        st.write("")

        # Row 2
        r2_c1, r2_c2 = st.columns(2, gap="large")
        with r2_c1:
            st.markdown("### 🚫 Threat Blocklist")
            st.markdown("Manage active global threat indicators (Emails, Domains, IPs) and security policies.")
            if st.button("Open Blocklist", use_container_width=True, type="primary"):
                st.session_state.ledger_subview = "blocklist"
                st.rerun()

        with r2_c2:
            st.markdown("### ⚙️ Data Management")
            st.markdown("Register new entries, update records, edit analyst notes, or purge legacy logs.")
            if st.button("Open Data Management", use_container_width=True, type="primary"):
                st.session_state.ledger_subview = "manage"
                st.rerun()

        st.write("")

        # Row 3 
        r3_c1, r3_c2 = st.columns(2, gap="large")
        with r3_c1:
            st.markdown("### 🖥️ Crash Reports")
            st.markdown("Review system diagnostic logs, database exceptions, and error tracebacks.")
            if st.button("Open Crash Reports", use_container_width=True, type="primary"):
                st.session_state.ledger_subview = "diagnostics"
                st.rerun()
        
        # --- (End of the existing Row 3 code) ---
        with r3_c2:
            st.empty()

    # --- UNIVERSAL FOOTER ---
    st.divider()
    tz_mode = "Local System Time" if str(st.session_state.get("tz_pref")).startswith("Local") else "UTC (Coordinated Universal Time)"
    st.caption(f"🕒 **Timezone Mode:** All database records and telemetry timestamps are currently displayed in **{tz_mode}**.")

    conn.close()