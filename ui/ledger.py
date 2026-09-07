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
    tab_cases, tab_pers, tab_blocks, tab_manage = st.tabs([
        "🗄️ Cases Vault", "👥 Personnel Roster", "🚫 Blocklist Indicators", "⚙️ Data Management"
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
    # TAB 2: PERSONNEL ROSTER
    # =========================================================
    with tab_pers:
        df_pers = pd.read_sql_query(
            "SELECT org_id, full_name, email, designation, notes, timestamp_added, last_modified FROM personnel ORDER BY full_name ASC", 
            conn
        )
        df_pers.insert(0, 'Row #', range(1, 1 + len(df_pers)))
        
        per_col1, per_col2 = st.columns([5, 2])
        with per_col1:
            st.dataframe(df_pers, use_container_width=True, hide_index=True)
        with per_col2:
            st.subheader("Roster Actions")
            csv_pers = df_pers.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Export Roster CSV",
                data=csv_pers,
                file_name="personnel_roster.csv",
                mime="text/csv",
                use_container_width=True
            )
            
            uploaded_pers = st.file_uploader("Bulk Upload Personnel (.csv)", type=["csv"], key="per_csv")
            if uploaded_pers is not None:
                if st.button("Process Roster CSV", use_container_width=True):
                    try:
                        imported_df = pd.read_csv(uploaded_pers)
                        inserted = 0
                        for _, row in imported_df.iterrows():
                            conn.execute("""
                                INSERT OR IGNORE INTO personnel (org_id, full_name, email, designation, notes)
                                VALUES (?, ?, ?, ?, ?)
                            """, (row.get('org_id', ''), row.get('full_name', ''), row.get('email', ''), row.get('designation', ''), row.get('notes', '')))
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
        
        # --- PERSONNEL MANAGEMENT ---
        with mgmt_col1:
            st.markdown("### 👥 Manage Personnel")
            per_action = st.radio("Action", ["Add New", "Edit Existing", "Delete Existing"], key="per_action", horizontal=True)
            
            if per_action == "Add New":
                with st.form("add_per_form"):
                    p_org_id = st.text_input("Organization ID", placeholder="e.g., EMP-101, STU-2026")
                    p_name = st.text_input("Full Name", placeholder="e.g., Jane Doe")
                    p_email = st.text_input("Official Email", placeholder="e.g., jane.doe@institution.edu")
                    p_role = st.text_input("Role / Title", placeholder="e.g., Faculty, Analyst, Student")
                    p_notes = st.text_area("Notes", placeholder="VIP user / High-risk target")
                    
                    if st.form_submit_button("Confirm Add"):
                        p_email_clean = p_email.strip().lower()
                        
                        if not p_org_id.strip():
                            st.error("❌ **Missing Data:** Organization ID is required. \n*Example: `FAC-402` or `EMP-101`*")
                        elif not p_name.strip():
                            st.error("❌ **Missing Data:** Full Name is required. \n*Example: `Jane Doe`*")
                        elif not p_email_clean:
                            st.error("❌ **Missing Data:** Official Email is required. \n*Example: `jane.doe@institution.edu`*")
                        elif not re.match(r"^[^@]+@[^@]+\.[^@]+$", p_email_clean):
                            st.error("❌ **Format Error:** Not a valid email address. \n*Example: `jane.doe@institution.edu`*")
                        else:
                            try:
                                conn.execute("""
                                    INSERT INTO personnel (org_id, full_name, email, designation, notes) 
                                    VALUES (?, ?, ?, ?, ?)
                                """, (p_org_id.strip(), p_name.strip(), p_email_clean, p_role.strip(), p_notes.strip()))
                                conn.commit()
                                st.success(f"✅ Personnel {p_name.strip()} successfully registered.")
                                st.rerun()
                            except Exception as e:
                                error_msg = str(e)
                                if "personnel.email" in error_msg:
                                    st.error(f"⚠️ **Duplicate Entry:** The email `{p_email_clean}` is already assigned.")
                                elif "personnel.org_id" in error_msg:
                                    st.error(f"⚠️ **Duplicate Entry:** The ID `{p_org_id.strip()}` is already in use.")
                                else:
                                    st.error(f"🚨 **Database Error:** {error_msg}")
                            
            elif per_action == "Edit Existing":
                if not df_pers.empty:
                    display_list = df_pers.apply(
                        lambda r: f"{r['org_id']} | {r['full_name']} ({r['email']})", axis=1
                    ).tolist()
                    
                    selected_display = st.selectbox("Select Personnel by ID", display_list)
                    target_org_id = selected_display.split(" | ")[0]
                    current_per = df_pers[df_pers["org_id"] == target_org_id].iloc[0]
                    
                    # 1. Safely cast database values to strings to prevent NoneType errors
                    safe_org_id = str(current_per["org_id"]) if current_per["org_id"] else ""
                    safe_name = str(current_per["full_name"]) if current_per["full_name"] else ""
                    safe_email = str(current_per["email"]) if current_per["email"] else ""
                    safe_role = str(current_per["designation"]) if current_per["designation"] else ""
                    safe_notes = str(current_per["notes"]) if current_per["notes"] else ""

                    with st.form("edit_per_form"):
                        new_org_id = st.text_input("Organization ID", value=safe_org_id)
                        new_name = st.text_input("Full Name", value=safe_name)
                        new_email = st.text_input("Official Email", value=safe_email)
                        new_role = st.text_input("Role / Title", value=safe_role)
                        new_notes = st.text_area("Notes", value=safe_notes)
                        
                        if st.form_submit_button("Update Personnel", type="primary"):
                            # 2. Safely cast to string before applying string methods like .strip()
                            new_email_clean = str(new_email).strip().lower() if new_email else ""
                            new_org_id_clean = str(new_org_id).strip() if new_org_id else ""
                            new_name_clean = str(new_name).strip() if new_name else ""
                            new_role_clean = str(new_role).strip() if new_role else ""
                            new_notes_clean = str(new_notes).strip() if new_notes else ""
                            
                            if not new_org_id_clean or not new_name_clean or not new_email_clean:
                                st.error("❌ **Missing Data:** ID, Name, and Email cannot be empty.")
                            elif not re.match(r"^[^@]+@[^@]+\.[^@]+$", new_email_clean):
                                st.error("❌ **Format Error:** Not a valid email address.")
                            else:
                                try:
                                    conn.execute("""
                                        UPDATE personnel 
                                        SET org_id = ?, full_name = ?, email = ?, designation = ?, notes = ?, last_modified = CURRENT_TIMESTAMP
                                        WHERE org_id = ?
                                    """, (new_org_id_clean, new_name_clean, new_email_clean, new_role_clean, new_notes_clean, target_org_id))
                                    conn.commit()
                                    st.success("Personnel record updated.")
                                    st.rerun()
                                except Exception as e:
                                    error_msg = str(e)
                                    if "UNIQUE constraint failed" in error_msg:
                                        st.error("⚠️ **Duplicate Entry:** That ID or Email conflicts with another user.")
                                    else:
                                        st.error(f"Error updating record: {e}")
                else:
                    st.info("No personnel to edit.")
                    
            elif per_action == "Delete Existing":
                if not df_pers.empty:
                    with st.form("del_per_form"):
                        display_list = df_pers.apply(
                            lambda r: f"{r['org_id']} | {r['full_name']} ({r['email']})", axis=1
                        ).tolist()
                        
                        selected_display = st.selectbox("Select Personnel to Remove", display_list)
                        target_org_id = selected_display.split(" | ")[0]
                        
                        if st.form_submit_button("Confirm Delete", type="primary"):
                            conn.execute("DELETE FROM personnel WHERE org_id = ?", (target_org_id,))
                            conn.commit()
                            st.success("Personnel removed.")
                            st.rerun()
                else:
                    st.info("No personnel to delete.")
                    
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
                        is_valid = True
                        
                        if not b_val_clean:
                            if b_type == "EMAIL":
                                st.error("❌ **Missing Data:** Please provide an email address. \n*Example: `attacker@phishmail.com`*")
                            elif b_type == "DOMAIN":
                                st.error("❌ **Missing Data:** Please provide a domain name. \n*Example: `evil-empire.com`*")
                            elif b_type == "IP":
                                st.error("❌ **Missing Data:** Please provide an IP address. \n*Example: `185.220.101.5`*")
                            is_valid = False
                        elif b_type == "EMAIL" and not re.match(r"^[^@]+@[^@]+\.[^@]+$", b_val_clean):
                            st.error("❌ **Format Error:** Not a valid email. \n*Example: `attacker@phishmail.com`*")
                            is_valid = False
                        elif b_type == "DOMAIN" and not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", b_val_clean):
                            st.error("❌ **Format Error:** Not a valid domain. Must include a TLD. \n*Example: `evil-empire.com`*")
                            is_valid = False
                        elif b_type == "IP":
                            try:
                                ipaddress.ip_address(b_val_clean)
                            except ValueError:
                                st.error("❌ **Format Error:** Not a valid IP address. \n*Example: `185.220.101.5`*")
                                is_valid = False

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
                        
                        safe_val = str(current_blk["indicator_value"]) if current_blk["indicator_value"] else ""
                        safe_reason = str(current_blk["reason"]) if current_blk["reason"] else ""
                        safe_notes = str(current_blk["notes"]) if current_blk["notes"] else ""
                        
                        new_val = st.text_input("Indicator Value", value=safe_val)
                        new_reason = st.text_input("Reason", value=safe_reason)
                        new_notes = st.text_area("Notes", value=safe_notes)
                        
                        if st.form_submit_button("Update Indicator", type="primary"):
                            b_val_clean = str(new_val).strip().lower() if new_val else ""
                            is_valid = True
                            
                            if not b_val_clean:
                                if new_type == "EMAIL": st.error("❌ **Missing Data:** Provide an email address.")
                                elif new_type == "DOMAIN": st.error("❌ **Missing Data:** Provide a domain name.")
                                elif new_type == "IP": st.error("❌ **Missing Data:** Provide an IP address.")
                                is_valid = False
                            elif new_type == "EMAIL" and not re.match(r"^[^@]+@[^@]+\.[^@]+$", b_val_clean):
                                st.error("❌ **Format Error:** Not a valid email.")
                                is_valid = False
                            elif new_type == "DOMAIN" and not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", b_val_clean):
                                st.error("❌ **Format Error:** Not a valid domain. Must include a TLD.")
                                is_valid = False
                            elif new_type == "IP":
                                try:
                                    ipaddress.ip_address(b_val_clean)
                                except ValueError:
                                    st.error("❌ **Format Error:** Not a valid IP.")
                                    is_valid = False
                                    
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