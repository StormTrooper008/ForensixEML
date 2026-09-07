import streamlit as st
import pandas as pd
import traceback
import os

def render_tab_diagnostics(conn):
    # 1. GUARANTEE TABLE & NOTES COLUMN EXIST
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS crash_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                error_message TEXT,
                traceback TEXT,
                user TEXT
            )
        """)
        conn.commit()
    except Exception:
        pass

    try:
        # Dynamically add the notes column if it doesn't exist yet
        conn.execute("ALTER TABLE crash_logs ADD COLUMN notes TEXT DEFAULT ''")
        conn.commit()
    except Exception:
        pass # Column already exists

    # 2. SUB-ROUTING FOR DIAGNOSTICS
    if "diag_subview" not in st.session_state:
        st.session_state.diag_subview = "overview"

    if st.session_state.diag_subview == "ledger":
        render_diagnostics_ledger(conn)
    else:
        render_diagnostics_overview(conn)

def render_diagnostics_overview(conn):
    st.markdown("### 🖥️ System Health & Overview")
    
    # Fetch counts for metrics
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM crash_logs")
        total_crashes = cursor.fetchone()[0]
    except Exception:
        total_crashes = 0

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Database Status", "Online & Healthy")
    with col2:
        st.metric("Total Logged Exceptions", total_crashes)

    st.write("")
    
    # Navigation & Actions
    action_c1, action_c2 = st.columns(2)
    with action_c1:
        st.markdown("#### 📂 Crash Reports")
        st.caption("Review tracebacks, add notes, and export system logs.")
        if st.button("View Crash Ledger", use_container_width=True, type="primary"):
            st.session_state.diag_subview = "ledger"
            st.rerun()
            
    with action_c2:
        if st.session_state.get("dev_mode", False):
            st.markdown("#### 🛠️ Dev Tools")
            st.caption("Will auto-delete when Dev Mode is turned off.")
            if st.button("🚨 Simulate Critical Crash", use_container_width=True):
                try:
                    x = 1 / 0
                except Exception as e:
                    error_msg = f"[SIMULATED] Division By Zero Test: {str(e)}"
                    tb_str = traceback.format_exc()
                    active_user = "Dev_Testing"
                    
                    conn.execute("""
                        INSERT INTO crash_logs (error_message, traceback, user, notes)
                        VALUES (?, ?, ?, ?)
                    """, (error_msg, tb_str, active_user, "Auto-generated test crash."))
                    conn.commit()
                    st.success("Test crash executed and logged to database successfully!")

def render_diagnostics_ledger(conn):
    nav_c1, nav_c2 = st.columns([4, 1])
    with nav_c1:
        if st.button("⬅️ Back to Health Overview"):
            st.session_state.diag_subview = "overview"
            st.rerun()
            
    st.divider()
    st.markdown("### 📋 Crash Reports Ledger")
    
    try:
        if str(st.session_state.get("tz_pref")).startswith("Local"):
            query = "SELECT id, datetime(timestamp, 'localtime') as timestamp, error_message, notes, user FROM crash_logs ORDER BY timestamp DESC"
        else:
            query = "SELECT id, timestamp, error_message, notes, user FROM crash_logs ORDER BY timestamp DESC"
            
        df_logs = pd.read_sql_query(query, conn)
    except Exception:
        df_logs = pd.DataFrame()

    if not df_logs.empty:
        # Export Button
        log_text_output = "=== SYSTEM CRASH DIAGNOSTIC LOGS ===\n\n"
        cursor = conn.cursor()
        cursor.execute("SELECT id, traceback FROM crash_logs")
        tracebacks = {row["id"]: row["traceback"] for row in cursor.fetchall()}
        
        for _, row in df_logs.iterrows():
            log_text_output += f"[{row['timestamp']}] ERROR: {row['error_message']}\n"
            log_text_output += f"NOTES: {row['notes']}\n"
            log_text_output += f"TRACEBACK:\n{tracebacks.get(row['id'], 'N/A')}\n"
            log_text_output += "="*80 + "\n\n"

        st.download_button("📥 Export Crash Logs (.log)", data=log_text_output, file_name="system_crash_reports.log", mime="text/plain")
        
        st.dataframe(df_logs, use_container_width=True, hide_index=True)
        
        # Details & Notes Editor
        st.subheader("Traceback Inspector & Notes")
        inspect_col, notes_col = st.columns([2, 1])
        
        selected_log_id = st.selectbox("Select Log ID to View/Edit:", df_logs["id"].tolist())
        
        if selected_log_id:
            with inspect_col:
                st.code(tracebacks.get(selected_log_id, "No traceback found."), language="python")
                
            with notes_col:
                # --- BULLETPROOF EXTRACTION LOGIC ---
                matched_row = df_logs[df_logs["id"] == selected_log_id]
                if not matched_row.empty:
                    raw_note = matched_row.iloc[0]["notes"]
                    # If it's a pandas NaN or SQLite None, default to an empty string
                    current_note = "" if pd.isna(raw_note) or raw_note is None else str(raw_note)
                else:
                    current_note = ""
                # ------------------------------------
                
                new_note = st.text_area("Analyst Notes:", value=current_note, height=150)
                if st.button("💾 Save Note", use_container_width=True):
                    conn.execute("UPDATE crash_logs SET notes = ? WHERE id = ?", (new_note, selected_log_id))
                    conn.commit()
                    st.success("Note saved!")
                    st.rerun()
    else:
        st.success("✨ Zero system crashes recorded. The ledger is empty.")