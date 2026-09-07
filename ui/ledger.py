import streamlit as st
import pandas as pd
import json
import io
from logic.database import get_db_connection

def render_ledger():
    # --- HEADER WITH REFRESH BUTTON ---
    header_col1, header_col2 = st.columns([5, 1])
    with header_col1:
        st.markdown("<h2>Organizational Ledger</h2>", unsafe_allow_html=True)
    with header_col2:
        st.write("") 
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.rerun()
    
    conn = get_db_connection()
    tab_cases, tab_emps, tab_blocks, tab_manage = st.tabs([
        "🗄️ Cases Vault", "👥 Employee Roster", "🚫 Blocklist Indicators", "⚙️ Data Management"
    ])
    
    # =========================================================
    # TAB 1: CASES VAULT
    # =========================================================
    with tab_cases:
        if st.session_state.get("tz_pref") == "Local":
            query = """
                SELECT status, risk_score, case_id, file_name, sender, origin_ip, 
                datetime(timestamp, 'localtime') as timestamp, 
                datetime(last_analyzed, 'localtime') as last_analyzed,
                notes
                FROM cases ORDER BY risk_score DESC
            """
        else:
            query = """
                SELECT status, risk_score, case_id, file_name, sender, origin_ip, timestamp, last_analyzed, notes 
                FROM cases ORDER BY risk_score DESC
            """
            
        df_cases = pd.read_sql_query(query, conn)
        
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

    # =========================================================
    # TAB 2: EMPLOYEE ROSTER (With CSV Import/Export)
    # =========================================================
    with tab_emps:
        df_emps = pd.read_sql_query("SELECT id, full_name, email, designation, notes, timestamp_added, last_modified FROM employees", conn)
        
        emp_col1, emp_col2 = st.columns([5, 2])
        with emp_col1:
            st.dataframe(df_emps, use_container_width=True, hide_index=True)
        with emp_col2:
            st.subheader("Roster Actions")
            # Export CSV
            csv_emps = df_emps.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Export Roster CSV",
                data=csv_emps,
                file_name="employee_roster.csv",
                mime="text/csv",
                use_container_width=True
            )
            
            # Import CSV
            uploaded_emps = st.file_uploader("Bulk Upload Employees (.csv)", type=["csv"], key="emp_csv")
            if uploaded_emps is not None:
                if st.button("Process Roster CSV", use_container_width=True):
                    try:
                        imported_df = pd.read_csv(uploaded_emps)
                        inserted = 0
                        for _, row in imported_df.iterrows():
                            conn.execute("""
                                INSERT OR IGNORE INTO employees (full_name, email, designation, notes)
                                VALUES (?, ?, ?, ?)
                            """, (row.get('full_name', ''), row.get('email', ''), row.get('designation', ''), row.get('notes', '')))
                            inserted += 1
                        conn.commit()
                        st.success(f"Successfully processed {inserted} records!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Import failed: {e}")

    # =========================================================
    # TAB 3: BLOCKLIST (With CSV Import/Export)
    # =========================================================
    with tab_blocks:
        df_blocks = pd.read_sql_query("SELECT id, indicator_type, indicator_value, reason, notes, timestamp_added, last_modified FROM blocklist", conn)
        
        blk_col1, blk_col2 = st.columns([5, 2])
        with blk_col1:
            st.dataframe(df_blocks, use_container_width=True, hide_index=True)
        with blk_col2:
            st.subheader("Indicator Actions")
            # Export CSV
            csv_blocks = df_blocks.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Export Blocklist CSV",
                data=csv_blocks,
                file_name="threat_blocklist.csv",
                mime="text/csv",
                use_container_width=True
            )
            
            # Import CSV
            uploaded_blocks = st.file_uploader("Bulk Upload Blocklist (.csv)", type=["csv"], key="blk_csv")
            if uploaded_blocks is not None:
                if st.button("Process Blocklist CSV", use_container_width=True):
                    try:
                        imported_blk = pd.read_csv(uploaded_blocks)
                        inserted = 0
                        for _, row in imported_blk.iterrows():
                            conn.execute("""
                                INSERT OR IGNORE INTO blocklist (indicator_type, indicator_value, reason, notes)
                                VALUES (?, ?, ?, ?)
                            """, (row.get('indicator_type', 'DOMAIN'), row.get('indicator_value', ''), row.get('reason', ''), row.get('notes', '')))
                            inserted += 1
                        conn.commit()
                        st.success(f"Successfully imported {inserted} indicators!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Import failed: {e}")
        
    # =========================================================
    # TAB 4: DATA MANAGEMENT (Cases, Employees & Blocklist)
    # =========================================================
    with tab_manage:
        st.markdown("### 🛠️ Case Vault Management")
        c_df = pd.read_sql_query("SELECT case_id, file_name, status, notes FROM cases ORDER BY timestamp DESC", conn)
        
        if not c_df.empty:
            case_action = st.radio("Case Action:", ["Add / Edit Notes", "Purge Case Record"], horizontal=True)
            target_case = st.selectbox("Select Target Case:", c_df["case_id"].tolist())
            
            if case_action == "Add / Edit Notes":
                current_note = c_df[c_df["case_id"] == target_case].iloc[0]["notes"]
                with st.form("edit_case_notes"):
                    new_note = st.text_area("Analyst Case Notes:", value=current_note if current_note else "")
                    if st.form_submit_button("Save Notes", type="primary"):
                        conn.execute("UPDATE cases SET notes = ? WHERE case_id = ?", (new_note, target_case))
                        conn.commit()
                        st.success(f"Notes updated for {target_case}.")
                        st.rerun()
                        
            elif case_action == "Purge Case Record":
                with st.form("delete_case_form"):
                    st.warning(f"Permanently remove {target_case} from the forensic vault?")
                    if st.form_submit_button("Confirm Deletion", type="primary"):
                        conn.execute("DELETE FROM cases WHERE case_id = ?", (target_case,))
                        conn.commit()
                        st.success(f"Case {target_case} purged.")
                        st.rerun()
        else:
            st.info("No cases available to modify.")
            
        st.divider()

        # Split into two columns for Employee and Blocklist Management
        mgmt_col1, mgmt_col2 = st.columns(2)
        
        # --- EMPLOYEE MANAGEMENT ---
        with mgmt_col1:
            st.markdown("### 👥 Manage Employees")
            emp_action = st.radio("Action", ["Add New", "Edit Existing", "Delete Existing"], key="emp_action", horizontal=True)
            
            if emp_action == "Add New":
                with st.form("add_emp_form"):
                    e_name = st.text_input("Full Legal Name")
                    e_email = st.text_input("Corporate Email")
                    e_role = st.text_input("Designation")
                    e_notes = st.text_area("Notes", placeholder="VIP user / High-risk target")
                    if st.form_submit_button("Confirm Add"):
                        try:
                            conn.execute("""
                                INSERT INTO employees (full_name, email, designation, notes) 
                                VALUES (?, ?, ?, ?)
                            """, (e_name, e_email, e_role, e_notes))
                            conn.commit()
                            st.success("Employee registered.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error: {e}")
                            
            elif emp_action == "Edit Existing":
                if not df_emps.empty:
                    target_emp_email = st.selectbox("Select Employee to Edit", df_emps["email"].tolist())
                    current_emp = df_emps[df_emps["email"] == target_emp_email].iloc[0]
                    
                    with st.form("edit_emp_form"):
                        new_name = st.text_input("Full Legal Name", value=current_emp["full_name"])
                        new_email = st.text_input("Corporate Email", value=current_emp["email"])
                        new_role = st.text_input("Designation", value=current_emp["designation"])
                        new_notes = st.text_area("Notes", value=current_emp["notes"] if current_emp["notes"] else "")
                        
                        if st.form_submit_button("Update Employee", type="primary"):
                            try:
                                conn.execute("""
                                    UPDATE employees 
                                    SET full_name = ?, email = ?, designation = ?, notes = ?, last_modified = CURRENT_TIMESTAMP
                                    WHERE email = ?
                                """, (new_name, new_email, new_role, new_notes, target_emp_email))
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
            st.markdown("### 🚫 Manage Blocklist")
            blk_action = st.radio("Action", ["Add New", "Edit Existing", "Delete Existing"], key="blk_action", horizontal=True)
            
            if blk_action == "Add New":
                with st.form("add_blk_form"):
                    b_type = st.selectbox("Type", ["EMAIL", "DOMAIN", "IP"])
                    b_val = st.text_input("Indicator Value")
                    b_reason = st.text_input("Reason")
                    b_notes = st.text_area("Notes", placeholder="Observed in campaign X")
                    if st.form_submit_button("Confirm Add"):
                        try:
                            conn.execute("""
                                INSERT INTO blocklist (indicator_type, indicator_value, reason, notes) 
                                VALUES (?, ?, ?, ?)
                            """, (b_type, b_val, b_reason, b_notes))
                            conn.commit()
                            st.success("Indicator blocked.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error: {e}")
                            
            elif blk_action == "Edit Existing":
                if not df_blocks.empty:
                    target_indicator = st.selectbox("Select Indicator to Edit", df_blocks["indicator_value"].tolist())
                    current_blk = df_blocks[df_blocks["indicator_value"] == target_indicator].iloc[0]
                    
                    with st.form("edit_blk_form"):
                        type_options = ["EMAIL", "DOMAIN", "IP"]
                        type_idx = type_options.index(current_blk["indicator_type"]) if current_blk["indicator_type"] in type_options else 0
                        
                        new_type = st.selectbox("Type", type_options, index=type_idx)
                        new_val = st.text_input("Indicator Value", value=current_blk["indicator_value"])
                        new_reason = st.text_input("Reason", value=current_blk["reason"])
                        new_notes = st.text_area("Notes", value=current_blk["notes"] if current_blk["notes"] else "")
                        
                        if st.form_submit_button("Update Indicator", type="primary"):
                            try:
                                conn.execute("""
                                    UPDATE blocklist 
                                    SET indicator_type = ?, indicator_value = ?, reason = ?, notes = ?, last_modified = CURRENT_TIMESTAMP
                                    WHERE indicator_value = ?
                                """, (new_type, new_val, new_reason, new_notes, target_indicator))
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