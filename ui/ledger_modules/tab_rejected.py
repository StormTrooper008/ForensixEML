import streamlit as st
import pandas as pd

def render_tab_rejected(conn):
    st.markdown("### 🗑️ Rejected Files Ledger")
    st.caption("Audit trail of malformed or corrupted emails blocked by the strict RFC 5322 ingestion sandbox.")

    # Mirroring your global timezone logic
    if str(st.session_state.get("tz_pref")).startswith("Local"):
        query = "SELECT id, file_name, rejection_reason, datetime(timestamp, 'localtime') as timestamp FROM rejected_files ORDER BY timestamp DESC"
    else:
        query = "SELECT id, file_name, rejection_reason, timestamp FROM rejected_files ORDER BY timestamp DESC"

    try:
        rejected_df = pd.read_sql_query(query, conn)
    except Exception:
        rejected_df = pd.DataFrame()

    if rejected_df.empty:
        st.success("✅ No files have been rejected yet.")
    else:
        # Search & Filter Bar (Matching your Vault UI)
        s_col1, s_col2 = st.columns([2, 1])
        with s_col1:
            query_text = st.text_input("🔍 Search Rejected Files...", key="rej_search").strip().lower()
        with s_col2:
            filter_col = st.selectbox("Filter Field", ["Any Field"] + list(rejected_df.columns), key="rej_filter")

        filtered_df = rejected_df.copy()
        if query_text:
            if filter_col == "Any Field":
                mask = filtered_df.astype(str).apply(lambda x: x.str.lower().str.contains(query_text).any(), axis=1)
                filtered_df = filtered_df[mask]
            else:
                filtered_df = filtered_df[filtered_df[filter_col].astype(str).str.lower().str.contains(query_text)]

        st.dataframe(
            filtered_df,
            use_container_width=True,
            hide_index=True
        )