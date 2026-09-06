import streamlit as st
import pandas as pd
import json
from logic.database import get_db_connection

def render_ledger():
    # --- NEW ALIGNED HEADER WITH REFRESH BUTTON ---
    header_col1, header_col2 = st.columns([5, 1])
    with header_col1:
        st.markdown("<h2>Organizational Ledger</h2>", unsafe_allow_html=True)
    with header_col2:
        st.write("") # Quick spacer to push the button down slightly so it aligns with the text
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.rerun()
    
    conn = get_db_connection()
    tab_cases, tab_emps, tab_blocks, tab_manage = st.tabs([
        "🗄️ Cases Vault", "👥 Employee Roster", "🚫 Blocklist Indicators", "⚙️ Data Management"
    ])
    
    # --- TAB 1: CASES VAULT ---
    with tab_cases:
        # Added 'last_analyzed' to the SELECT statement
        df_cases = pd.read_sql_query(
            "SELECT status, risk_score, case_id, file_name, sender, origin_ip, timestamp, last_analyzed FROM cases ORDER BY risk_score DESC", 
            conn
        )
        
        col1, col2 = st.columns([3, 1])
        with col1:
            st.dataframe(df_cases, use_container_width=True, hide_index=True)
        with col2:
            st.subheader("Load Historical Case")
            if not df_cases.empty:
                selected_case = st.selectbox("Select Case ID to Load:", df_cases["case_id"].tolist())
                if st.button("Load into Workbench", type="primary", use_container_width=True):
                    cursor = conn.cursor()
                    cursor.execute("SELECT file_name, sha256, status, risk_score, telemetry FROM cases WHERE case_id = ?", (selected_case,))
                    row = cursor.fetchone()
                    
                    if row and row["telemetry"]:
                        tel = json.loads(row["telemetry"])
                        st.session_state.analyzed_store[selected_case] = {
                            "case_id": selected_case,
                            "file_name": row["file_name"],
                            "hash": row["sha256"],
                            "status": row["status"],
                            "risk_score": row["risk_score"],
                            "decomp": tel.get("decomp", {}),
                            "auth": tel.get("auth", {}),
                            "geo": tel.get("geo", {}),
                            "heur": tel.get("heur", {}),
                            "intel": tel.get("intel", {})
                        }
                        st.session_state.selected_case = selected_case
                        st.session_state.current_page = "🔬 Investigation Workbench"
                        st.rerun()
                    else:
                        st.error("No telemetry data exists for this older case. Please re-ingest the file.")
            else:
                st.info("Vault is empty.")

    # --- TAB 2: EMPLOYEE ROSTER ---
    with tab_emps:
        df_emps = pd.read_sql_query("SELECT id, full_name, email, designation FROM employees", conn)
        st.dataframe(df_emps, use_container_width=True, hide_index=True)
            
    # --- TAB 3: BLOCKLIST ---
    with tab_blocks:
        df_blocks = pd.read_sql_query("SELECT id, indicator_type, indicator_value, reason FROM blocklist", conn)
        st.dataframe(df_blocks, use_container_width=True, hide_index=True)
        
    # --- TAB 4: DATA MANAGEMENT (Add/Edit/Delete) ---
    with tab_manage:
        mgmt_col1, mgmt_col2 = st.columns(2)
        
        # --- EMPLOYEE MANAGEMENT ---
        with mgmt_col1:
            st.subheader("Manage Employees")
            emp_action = st.radio("Action", ["Add New", "Edit Existing", "Delete Existing"], key="emp_action", horizontal=True)
            
            if emp_action == "Add New":
                with st.form("add_emp_form"):
                    e_name = st.text_input("Full Legal Name")
                    e_email = st.text_input("Corporate Email")
                    e_role = st.text_input("Designation")
                    if st.form_submit_button("Confirm Add"):
                        try:
                            conn.execute("INSERT INTO employees (full_name, email, designation) VALUES (?, ?, ?)", (e_name, e_email, e_role))
                            conn.commit()
                            st.success("Employee added.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error: {e}")
                            
            elif emp_action == "Edit Existing":
                if not df_emps.empty:
                    target_emp_email = st.selectbox("Select Employee", df_emps["email"].tolist())
                    # Retrieve the specific employee's current data
                    current_emp = df_emps[df_emps["email"] == target_emp_email].iloc[0]
                    
                    with st.form("edit_emp_form"):
                        new_name = st.text_input("Full Legal Name", value=current_emp["full_name"])
                        new_email = st.text_input("Corporate Email", value=current_emp["email"])
                        new_role = st.text_input("Designation", value=current_emp["designation"])
                        
                        if st.form_submit_button("Update Employee", type="primary"):
                            try:
                                conn.execute("""
                                    UPDATE employees 
                                    SET full_name = ?, email = ?, designation = ? 
                                    WHERE email = ?
                                """, (new_name, new_email, new_role, target_emp_email))
                                conn.commit()
                                st.success("Employee updated.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Error updating record: {e}")
                else:
                    st.info("No employees to edit.")

            elif emp_action == "Delete Existing":
                if not df_emps.empty:
                    with st.form("del_emp_form"):
                        del_target = st.selectbox("Select Employee to Remove", df_emps["email"].tolist())
                        if st.form_submit_button("Confirm Delete", type="primary"):
                            conn.execute("DELETE FROM employees WHERE email = ?", (del_target,))
                            conn.commit()
                            st.success("Employee removed.")
                            st.rerun()
                else:
                    st.info("No employees to delete.")
                    
        # --- BLOCKLIST MANAGEMENT ---
        with mgmt_col2:
            st.subheader("Manage Blocklist")
            blk_action = st.radio("Action", ["Add New", "Edit Existing", "Delete Existing"], key="blk_action", horizontal=True)
            
            if blk_action == "Add New":
                with st.form("add_blk_form"):
                    b_type = st.selectbox("Type", ["EMAIL", "DOMAIN", "IP"])
                    b_val = st.text_input("Indicator Value")
                    b_reason = st.text_input("Reason")
                    if st.form_submit_button("Confirm Add"):
                        try:
                            conn.execute("INSERT INTO blocklist (indicator_type, indicator_value, reason) VALUES (?, ?, ?)", (b_type, b_val, b_reason))
                            conn.commit()
                            st.success("Indicator blocked.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error: {e}")
                            
            elif blk_action == "Edit Existing":
                if not df_blocks.empty:
                    target_indicator = st.selectbox("Select Indicator", df_blocks["indicator_value"].tolist())
                    # Retrieve the specific indicator's current data
                    current_blk = df_blocks[df_blocks["indicator_value"] == target_indicator].iloc[0]
                    
                    with st.form("edit_blk_form"):
                        # Get index of current type to set it as default in selectbox
                        type_options = ["EMAIL", "DOMAIN", "IP"]
                        type_idx = type_options.index(current_blk["indicator_type"]) if current_blk["indicator_type"] in type_options else 0
                        
                        new_type = st.selectbox("Type", type_options, index=type_idx)
                        new_val = st.text_input("Indicator Value", value=current_blk["indicator_value"])
                        new_reason = st.text_input("Reason", value=current_blk["reason"])
                        
                        if st.form_submit_button("Update Indicator", type="primary"):
                            try:
                                conn.execute("""
                                    UPDATE blocklist 
                                    SET indicator_type = ?, indicator_value = ?, reason = ? 
                                    WHERE indicator_value = ?
                                """, (new_type, new_val, new_reason, target_indicator))
                                conn.commit()
                                st.success("Indicator updated.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Error updating record: {e}")
                else:
                    st.info("Blocklist is empty.")
                            
            elif blk_action == "Delete Existing":
                if not df_blocks.empty:
                    with st.form("del_blk_form"):
                        del_target_blk = st.selectbox("Select Indicator to Unblock", df_blocks["indicator_value"].tolist())
                        if st.form_submit_button("Confirm Delete", type="primary"):
                            conn.execute("DELETE FROM blocklist WHERE indicator_value = ?", (del_target_blk,))
                            conn.commit()
                            st.success("Indicator removed.")
                            st.rerun()
                else:
                    st.info("Blocklist is empty.")
                    
    conn.close()