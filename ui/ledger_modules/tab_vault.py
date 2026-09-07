import streamlit as st
import pandas as pd
import json

def render_tab_vault(conn):
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