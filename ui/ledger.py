import streamlit as st
import pandas as pd
import json
import io
import re
import ipaddress

from logic.database import get_db_connection

def render_ledger():
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
    # TAB 2: EMPLOYEE ROSTER
    # =========================================================
    with tab_emps:
        df_emps = pd.read_sql_query(
            "SELECT emp_id, full_name, email, designation, notes, timestamp_added, last_modified FROM employees ORDER BY full_name ASC", 
            conn
        )
        df_emps.insert(0, 'Row #', range(1, 1 + len(df_emps)))
        
        emp_col1, emp_col2 = st.columns([5, 2])
        with emp_col1:
            st.dataframe(df_emps, use_container_width=True, hide_index=True)
        with emp_col2:
            st.subheader("Roster Actions")
            csv_emps = df_emps.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Export Roster CSV",
                data=csv_emps,
                file_name="employee_roster.csv",
                mime="text/csv",
                use_container_width=True
            )
            
            uploaded_emps = st.file_uploader("Bulk Upload Employees (.csv)", type=["csv"], key="emp_csv")
            if uploaded_emps is not None:
                if st.button("Process Roster CSV", use_container_width=True):
                    try:
                        imported_df = pd.read_csv(uploaded_emps)
                        inserted = 0
                        for _, row in imported_df.iterrows():
                            conn.execute("""
                                INSERT OR IGNORE INTO employees (emp_id, full_name, email, designation, notes)
                                VALUES (?, ?, ?, ?, ?)
                            """, (row.get('emp_id', ''), row.get('full_name', ''), row.get('email', ''), row.get('designation', ''), row.get('notes', '')))
                            inserted += 1
                        conn.commit()
                        st.success(f"Successfully processed {inserted} records!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Import failed: {e}")

    # =========================================================
    # TAB 3: BLOCKLIST
    # =========================================================
    with tab_blocks:
        df_blocks = pd.read_sql_query(
            "SELECT indicator_type, indicator_value, reason, notes, timestamp_added, last_modified FROM blocklist ORDER BY timestamp_added DESC", 
            conn
        )
        df_blocks.insert(0, 'Row #', range(1, 1 + len(df_blocks)))
        
        blk_col1, blk_col2 = st.columns([5, 2])
        with blk_col1:
            st.dataframe(df_blocks, use_container_width=True, hide_index=True)
        with blk_col2:
            st.subheader("Indicator Actions")
            csv_blocks = df_blocks.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Export Blocklist CSV",
                data=csv_blocks,
                file_name="threat_blocklist.csv",
                mime="text/csv",
                use_container_width=True
            )
            
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
    # TAB 4: DATA MANAGEMENT
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

        mgmt_col1, mgmt_col2 = st.columns(2)
        
        # --- EMPLOYEE MANAGEMENT ---
        with mgmt_col1:
            st.markdown("### 👥 Manage Employees")
            emp_action = st.radio("Action", ["Add New", "Edit Existing", "Delete Existing"], key="emp_action", horizontal=True)
            
            if emp_action == "Add New":
                with st.form("add_emp_form"):
                    e_emp_id = st.text_input("Corporate Employee ID", placeholder="e.g., EMP-101")
                    e_name = st.text_input("Full Legal Name", placeholder="e.g., Jane Doe")
                    e_email = st.text_input("Corporate Email", placeholder="e.g., jane.doe@corp.com")
                    e_role = st.text_input("Designation", placeholder="e.g., Financial Controller")
                    e_notes = st.text_area("Notes", placeholder="VIP user / High-risk target")
                    
                    if st.form_submit_button("Confirm Add"):
                        # 1. Check for empty mandatory fields with specific examples
                        if not e_emp_id.strip():
                            st.error("❌ **Missing Data:** Corporate Employee ID is required. \n*Example: `EMP-101`*")
                        elif not e_name.strip():
                            st.error("❌ **Missing Data:** Full Legal Name is required. \n*Example: `Jane Doe`*")
                        elif not e_email.strip():
                            st.error("❌ **Missing Data:** Corporate Email is required. \n*Example: `jane.doe@corp.com`*")
                        else:
                            # 2. Database Insertion with specific duplicate tracking
                            try:
                                conn.execute("""
                                    INSERT INTO employees (emp_id, full_name, email, designation, notes) 
                                    VALUES (?, ?, ?, ?, ?)
                                """, (e_emp_id.strip(), e_name.strip(), e_email.strip(), e_role.strip(), e_notes.strip()))
                                conn.commit()
                                st.success(f"✅ Employee {e_name} successfully registered.")
                                st.rerun()
                            except Exception as e:
                                error_msg = str(e)
                                # Catch specific SQLite UNIQUE constraint errors
                                if "employees.email" in error_msg:
                                    st.error(f"⚠️ **Duplicate Entry:** The email `{e_email}` is already assigned to another employee.")
                                elif "employees.emp_id" in error_msg:
                                    st.error(f"⚠️ **Duplicate Entry:** The ID `{e_emp_id}` is already in use by another employee.")
                                else:
                                    st.error(f"🚨 **Database Error:** {error_msg}")
                
            elif emp_action == "Edit Existing":
                if not df_emps.empty:
                    display_list = df_emps.apply(
                        lambda r: f"{r['emp_id']} | {r['full_name']} ({r['email']})", axis=1
                    ).tolist()
                    
                    selected_display = st.selectbox("Select Employee by ID", display_list)
                    target_emp_id = selected_display.split(" | ")[0]
                    current_emp = df_emps[df_emps["emp_id"] == target_emp_id].iloc[0]
                    
                    with st.form("edit_emp_form"):
                        new_emp_id = st.text_input("Corporate Employee ID", value=current_emp["emp_id"])
                        new_name = st.text_input("Full Legal Name", value=current_emp["full_name"])
                        new_email = st.text_input("Corporate Email", value=current_emp["email"])
                        new_role = st.text_input("Designation", value=current_emp["designation"])
                        new_notes = st.text_area("Notes", value=current_emp["notes"] if current_emp["notes"] else "")
                        
                        if st.form_submit_button("Update Employee", type="primary"):
                            try:
                                conn.execute("""
                                    UPDATE employees 
                                    SET emp_id = ?, full_name = ?, email = ?, designation = ?, notes = ?, last_modified = CURRENT_TIMESTAMP
                                    WHERE emp_id = ?
                                """, (new_emp_id, new_name, new_email, new_role, new_notes, target_emp_id))
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
                        display_list = df_emps.apply(
                            lambda r: f"{r['emp_id']} | {r['full_name']} ({r['email']})", axis=1
                        ).tolist()
                        
                        selected_display = st.selectbox("Select Employee by ID to Remove", display_list)
                        target_emp_id = selected_display.split(" | ")[0]
                        
                        if st.form_submit_button("Confirm Delete", type="primary"):
                            conn.execute("DELETE FROM employees WHERE emp_id = ?", (target_emp_id,))
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
                        b_val_clean = b_val.strip().lower()
                        
                        # 1. Dynamic check for empty values with specific examples
                        if not b_val_clean:
                            if b_type == "EMAIL":
                                st.error("❌ **Missing Data:** Please provide an email address. \n*Example: `attacker@phishmail.com`*")
                            elif b_type == "DOMAIN":
                                st.error("❌ **Missing Data:** Please provide a domain name. \n*Example: `evil-empire.com`*")
                            elif b_type == "IP":
                                st.error("❌ **Missing Data:** Please provide an IP address. \n*Example: `185.220.101.5`*")
                        else:
                            # 2. Strict Format Validation
                            is_valid = True
                            
                            if b_type == "EMAIL" and not re.match(r"^[^@]+@[^@]+\.[^@]+$", b_val_clean):
                                st.error("❌ **Format Error:** Not a valid email. \n*Example: `attacker@phishmail.com`*")
                                is_valid = False
                                
                            elif b_type == "DOMAIN":
                                # Forces at least one dot and a 2+ character TLD (.com, .in)
                                if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", b_val_clean):
                                    st.error("❌ **Format Error:** Not a valid domain. Must include a TLD (like .com). \n*Example: `evil-empire.com`*")
                                    is_valid = False
                                    
                            elif b_type == "IP":
                                # Uses Python's native networking library to prove it is a real IP
                                try:
                                    ipaddress.ip_address(b_val_clean)
                                except ValueError:
                                    st.error("❌ **Format Error:** Not a mathematically valid IPv4 or IPv6 address. \n*Example: `185.220.101.5`*")
                                    is_valid = False

                            # 3. Database Insertion
                            if is_valid:
                                try:
                                    conn.execute("""
                                        INSERT INTO blocklist (indicator_type, indicator_value, reason, notes) 
                                        VALUES (?, ?, ?, ?)
                                    """, (b_type, b_val_clean, b_reason, b_notes))
                                    conn.commit()
                                    st.success(f"✅ {b_type} Indicator securely blocked.")
                                    st.rerun()
                                except Exception as e:
                                    error_msg = str(e)
                                    if "UNIQUE constraint failed" in error_msg:
                                        st.error(f"⚠️ **Duplicate Entry:** `{b_val_clean}` is already in your blocklist.")
                                    else:
                                        st.error(f"🚨 **Database Error:** {error_msg}")
                            
            elif blk_action == "Edit Existing":
                if not df_blocks.empty:
                    target_indicator = st.selectbox("Select Indicator to Edit", df_blocks["indicator_value"].tolist())
                    current_blk = df_blocks[df_blocks["indicator_value"] == target_indicator].iloc[0]
                    
                    with st.form("edit_blk_form"):
                        type_options = ["EMAIL", "DOMAIN", "IP"]
                        type_idx = type_options.index(current_blk["indicator_type"]) if current_blk["indicator_type"] in type_options else 0
                        
                        new_type = st.selectbox("Type", type_options, index=type_idx)
                        
                        # Safely cast database values to strings to prevent NoneType errors
                        safe_val = str(current_blk["indicator_value"]) if current_blk["indicator_value"] else ""
                        safe_reason = str(current_blk["reason"]) if current_blk["reason"] else ""
                        safe_notes = str(current_blk["notes"]) if current_blk["notes"] else ""
                        
                        new_val = st.text_input("Indicator Value", value=safe_val)
                        new_reason = st.text_input("Reason", value=safe_reason)
                        new_notes = st.text_area("Notes", value=safe_notes)
                        
                        if st.form_submit_button("Update Indicator", type="primary"):
                            # Safely handle the formatting
                            b_val_clean = str(new_val).strip().lower() if new_val else ""
                            is_valid = True
                            
                            # 1. Dynamic check for empty values with specific examples
                            if not b_val_clean:
                                if new_type == "EMAIL":
                                    st.error("❌ **Missing Data:** Please provide an email address. \n*Example: `attacker@phishmail.com`*")
                                elif new_type == "DOMAIN":
                                    st.error("❌ **Missing Data:** Please provide a domain name. \n*Example: `evil-empire.com`*")
                                elif new_type == "IP":
                                    st.error("❌ **Missing Data:** Please provide an IP address. \n*Example: `185.220.101.5`*")
                                is_valid = False
                                
                            # 2. Strict Format Validation
                            elif new_type == "EMAIL" and not re.match(r"^[^@]+@[^@]+\.[^@]+$", b_val_clean):
                                st.error("❌ **Format Error:** Not a valid email. \n*Example: `attacker@phishmail.com`*")
                                is_valid = False
                            elif new_type == "DOMAIN" and not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", b_val_clean):
                                st.error("❌ **Format Error:** Not a valid domain. Must include a TLD. \n*Example: `evil-empire.com`*")
                                is_valid = False
                            elif new_type == "IP":
                                try:
                                    ipaddress.ip_address(b_val_clean)
                                except ValueError:
                                    st.error("❌ **Format Error:** Not a valid IP. \n*Example: `185.220.101.5`*")
                                    is_valid = False
                                    
                            # 3. Database Update
                            if is_valid:
                                try:
                                    conn.execute("""
                                        UPDATE blocklist 
                                        SET indicator_type = ?, indicator_value = ?, reason = ?, notes = ?, last_modified = CURRENT_TIMESTAMP
                                        WHERE indicator_value = ?
                                    """, (new_type, b_val_clean, new_reason, new_notes, target_indicator))
                                    conn.commit()
                                    st.success("Indicator updated.")
                                    st.rerun()
                                except Exception as e:
                                    error_msg = str(e)
                                    if "UNIQUE constraint failed" in error_msg:
                                        st.error(f"⚠️ **Duplicate Entry:** `{b_val_clean}` is already in your blocklist.")
                                    else:
                                        st.error(f"🚨 **Database Error:** {error_msg}")
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