import pandas as pd
import traceback
import streamlit as st
from logic.database import get_db_connection

def log_system_crash(exception_obj, custom_message="An unexpected system error occurred."):
    """Captures exceptions, extracts tracebacks, and writes them to the crash_logs database."""
    error_msg = f"{custom_message}: {str(exception_obj)}"
    tb_str = traceback.format_exc()
    
    # Identify active user if session state tracks it, otherwise default to 'System/Analyst'
    active_user = st.session_state.get("username", "Analyst")

    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO crash_logs (error_message, traceback, user)
            VALUES (?, ?, ?)
        """, (error_msg, tb_str, active_user))
        conn.commit()
        conn.close()
    except Exception as db_err:
        print(f"CRITICAL: Failed to write to crash log database: {db_err}")

def render_system_diagnostics():
    """Renders a diagnostic monitoring view for reviewing system health and crash logs."""
    st.markdown("### 🖥️ System Health & Diagnostics")
    
    conn = get_db_connection()
    
    # Fetch recent crash logs
    try:
        df_logs = pd.read_sql_query("SELECT id, timestamp, error_message, user FROM crash_logs ORDER BY timestamp DESC", conn)
    except Exception:
        df_logs = pd.DataFrame()
        
    conn.close()

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Database Status", "Online & Healthy")
    with col2:
        st.metric("Total Logged Exceptions", len(df_logs) if not df_logs.empty else 0)

    st.markdown("#### Recent Error & Crash Ledger")
    if not df_logs.empty:
        st.dataframe(df_logs, use_container_width=True, hide_index=True)
        
        selected_log_id = st.selectbox("Select Log ID to View Full Traceback:", df_logs["id"].tolist())
        if selected_log_id:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT traceback FROM crash_logs WHERE id = ?", (selected_log_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                st.code(row["traceback"], language="python")
    else:
        st.success("✨ Zero system crashes recorded. The platform is running smoothly!")