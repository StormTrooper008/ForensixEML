import streamlit as st
import pandas as pd
from logic.database import get_db_connection

def render_ledger():
    st.markdown("<h2>Organizational Ledger</h2>", unsafe_allow_html=True)
    st.caption("Access historical cases, internal users, and blocklists.")
    
    conn = get_db_connection()
    tab_cases, tab_emps, tab_blocks = st.tabs(["Cases Vault", "Employee Roster", "Blocklist Indicators"])
    
    with tab_cases:
        df_cases = pd.read_sql_query("SELECT * FROM cases ORDER BY timestamp DESC", conn)
        st.dataframe(df_cases, use_container_width=True)
        
    with tab_emps:
        df_emps = pd.read_sql_query("SELECT * FROM employees", conn)
        st.dataframe(df_emps, use_container_width=True)
        
    with tab_blocks:
        df_blocks = pd.read_sql_query("SELECT * FROM blocklist", conn)
        st.dataframe(df_blocks, use_container_width=True)
        
    conn.close()