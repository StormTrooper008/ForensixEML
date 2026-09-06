import streamlit as st
import pandas as pd
from logic.database import get_db_connection

def render_ledger():
    st.markdown("<h2>Organizational Ledger</h2>", unsafe_allow_html=True)
    st.caption("Manage historical cases, internal users, and blocklists.")
    
    conn = get_db_connection()
    tab_cases, tab_emps, tab_blocks = st.tabs(["Cases Vault", "Employee Roster", "Blocklist Indicators"])
    
    # --- CASES TAB ---
    with tab_cases:
        df_cases = pd.read_sql_query("SELECT * FROM cases ORDER BY timestamp DESC", conn)
        st.dataframe(df_cases, use_container_width=True, hide_index=True)
        
    # --- EMPLOYEES TAB ---
    with tab_emps:
        col1, col2 = st.columns([1, 2])
        
        with col1:
            with st.form("add_employee_form"):
                st.subheader("Add Employee")
                emp_name = st.text_input("Full Legal Name", placeholder="e.g., John Doe")
                emp_email = st.text_input("Corporate Email", placeholder="johndoe@company.com")
                emp_role = st.text_input("Designation / Role", placeholder="CEO")
                
                if st.form_submit_button("Register Employee", use_container_width=True):
                    if emp_name and emp_email:
                        try:
                            conn.execute(
                                "INSERT INTO employees (full_name, email, designation) VALUES (?, ?, ?)", 
                                (emp_name, emp_email, emp_role)
                            )
                            conn.commit()
                            st.success(f"Added {emp_name} to roster.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Database Error: Might be a duplicate email. ({e})")
                    else:
                        st.warning("Name and Email are required.")
                        
        with col2:
            df_emps = pd.read_sql_query("SELECT id, full_name, email, designation FROM employees", conn)
            st.dataframe(df_emps, use_container_width=True, hide_index=True)
            
    # --- BLOCKLIST TAB ---
    with tab_blocks:
        col1, col2 = st.columns([1, 2])
        
        with col1:
            with st.form("add_blocklist_form"):
                st.subheader("Add Threat Indicator")
                ind_type = st.selectbox("Indicator Type", ["EMAIL", "DOMAIN", "IP"])
                ind_val = st.text_input("Indicator Value", placeholder="e.g., evil-phishing.com")
                ind_reason = st.text_input("Reason / Context", placeholder="Known malware distributor")
                
                if st.form_submit_button("Add to Blocklist", use_container_width=True):
                    if ind_val:
                        try:
                            conn.execute(
                                "INSERT INTO blocklist (indicator_type, indicator_value, reason) VALUES (?, ?, ?)", 
                                (ind_type, ind_val, ind_reason)
                            )
                            conn.commit()
                            st.success(f"Added {ind_val} to blocklist.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Database Error: Indicator likely already exists. ({e})")
                    else:
                        st.warning("Indicator Value is required.")
                        
        with col2:
            df_blocks = pd.read_sql_query("SELECT id, indicator_type, indicator_value, reason FROM blocklist", conn)
            st.dataframe(df_blocks, use_container_width=True, hide_index=True)
            
    conn.close()