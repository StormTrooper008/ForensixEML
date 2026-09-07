import streamlit as st
from logic.database import get_db_connection

# Import modularized tabs
from ui.ledger_modules.tab_vault import render_tab_vault
from ui.ledger_modules.tab_personnel import render_tab_personnel
from ui.ledger_modules.tab_blocklist import render_tab_blocklist
from ui.ledger_modules.tab_manage import render_tab_manage

def render_ledger():
    header_col1, header_col2 = st.columns([5, 1])
    with header_col1:
        st.markdown("<h2>Organizational Ledger</h2>", unsafe_allow_html=True)
    with header_col2:
        st.write("") 
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.rerun()
    
    conn = get_db_connection()
    tab_cases, tab_pers, tab_blocks, tab_manage = st.tabs([
        "🗄️ Cases Vault", "👥 Personnel Roster", "🚫 Blocklist Indicators", "⚙️ Data Management"
    ])
    
    with tab_cases:
        render_tab_vault(conn)
    with tab_pers:
        render_tab_personnel(conn)
    with tab_blocks:
        render_tab_blocklist(conn)
    with tab_manage:
        render_tab_manage(conn)
        
    conn.close()