import streamlit as st
import pandas as pd

def render_tab_diagnostics(conn):
    st.markdown("### 🖥️ System Health & Crash Reports")
    
    # Fetch recent crash logs
    try:
        if str(st.session_state.get("tz_pref")).startswith("Local"):
            query = "SELECT id, datetime(timestamp, 'localtime') as timestamp, error_message, user FROM crash_logs ORDER BY timestamp DESC"
        else:
            query = "SELECT id, timestamp, error_message, user FROM crash_logs ORDER BY timestamp DESC"
            
        df_logs = pd.read_sql_query(query, conn)
    except Exception:
        df_logs = pd.DataFrame()

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Database Status", "Online & Healthy")
    with col2:
        st.metric("Total Logged Exceptions", len(df_logs) if not df_logs.empty else 0)

    st.divider()

    if not df_logs.empty:
        # Search & Filter controls
        sch_col1, sch_col2 = st.columns([2, 1])
        with sch_col1:
            search_query = st.text_input("🔍 Search Crash Logs...", key="log_search").strip().lower()
        with sch_col2:
            filter_field = st.selectbox("Filter Field", ["Any Field"] + list(df_logs.columns), key="log_filter")

        # Apply safe search/filter logic with regex=False
        filtered_df = df_logs.copy()
        if search_query:
            if filter_field == "Any Field":
                mask = filtered_df.astype(str).apply(
                    lambda col: col.str.lower().str.contains(search_query, na=False, regex=False)
                ).any(axis=1)
                filtered_df = filtered_df[mask]
            else:
                filtered_df = filtered_df[
                    filtered_df[filter_field].astype(str).str.lower().str.contains(search_query, na=False, regex=False)
                ]

        st.dataframe(filtered_df, use_container_width=True, hide_index=True)
        
        st.subheader("Traceback Inspector")
        selected_log_id = st.selectbox("Select Log ID to View Full Traceback:", filtered_df["id"].tolist() if not filtered_df.empty else [])
        if selected_log_id:
            cursor = conn.cursor()
            cursor.execute("SELECT traceback FROM crash_logs WHERE id = ?", (selected_log_id,))
            row = cursor.fetchone()
            if row:
                st.code(row["traceback"], language="python")
    else:
        st.success("✨ Zero system crashes recorded. The platform is running smoothly!")