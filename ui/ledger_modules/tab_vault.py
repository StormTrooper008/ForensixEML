import streamlit as st
import pandas as pd
import json

def render_tab_vault(conn):
    st.markdown("### 🗄️ Cases Vault")
    if str(st.session_state.get("tz_pref")).startswith("Local"):
        query = """
            SELECT status, risk_score, case_id, file_name, sender, origin_ip, 
            datetime(timestamp, 'localtime') as timestamp, 
            datetime(last_analyzed, 'localtime') as last_analyzed,
            notes, ai_notes
            FROM cases ORDER BY risk_score DESC
        """
    else:
        query = """
            SELECT status, risk_score, case_id, file_name, sender, origin_ip, timestamp, last_analyzed, notes, ai_notes 
            FROM cases ORDER BY risk_score DESC
        """
        
    df_cases = pd.read_sql_query(query, conn)
    
    if not df_cases.empty:
        # Search & Filter Bar
        s_col1, s_col2 = st.columns([2, 1])
        with s_col1:
            query_text = st.text_input("🔍 Search Cases...", key="vault_search").strip().lower()
        with s_col2:
            filter_col = st.selectbox("Filter Field", ["Any Field"] + list(df_cases.columns), key="vault_filter")

        filtered_df = df_cases.copy()
        if query_text:
            if filter_col == "Any Field":
                mask = filtered_df.astype(str).apply(lambda x: x.str.lower().str.contains(query_text).any(), axis=1)
                filtered_df = filtered_df[mask]
            else:
                filtered_df = filtered_df[filtered_df[filter_col].astype(str).str.lower().str.contains(query_text)]

        col1, col2 = st.columns([3, 1])
        with col1:
            st.dataframe(filtered_df, use_container_width=True, hide_index=True)
        with col2:
            st.subheader("Load Historical Case")
            selected_case = st.selectbox("Select Case ID to Load:", filtered_df["case_id"].tolist() if not filtered_df.empty else [])
            if selected_case and st.button("Load into Workbench", type="primary", use_container_width=True):
                cursor = conn.cursor()
                # Grab ai_notes from the database so it loads into the workbench properly
                cursor.execute("SELECT file_name, sha256, status, risk_score, telemetry, ai_notes FROM cases WHERE case_id = ?", (selected_case,))
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
                        "intel": tel.get("intel", {}),
                        "ai_insight": row["ai_notes"]
                    }
                    st.session_state.selected_case = selected_case
                    st.session_state.current_page = "🔬 Investigation Workbench"
                    st.rerun()
                else:
                    st.error("No telemetry data exists for this older case.")
    else:
        st.info("Vault is empty.")