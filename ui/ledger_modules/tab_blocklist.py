import streamlit as st
import pandas as pd

def render_tab_blocklist(conn):
    st.markdown("### 🚫 Threat Blocklist Indicators")
    if str(st.session_state.get("tz_pref")).startswith("Local"):
        query = """SELECT indicator_type, indicator_value, reason, notes, 
                   datetime(timestamp_added, 'localtime') as timestamp_added, 
                   datetime(last_modified, 'localtime') as last_modified 
                   FROM blocklist ORDER BY timestamp_added DESC"""
    else:
        query = """SELECT indicator_type, indicator_value, reason, notes, 
                   timestamp_added, last_modified 
                   FROM blocklist ORDER BY timestamp_added DESC"""
                   
    df_blocks = pd.read_sql_query(query, conn)
    
    # 1. Force columns to ALWAYS render
    blk_col1, blk_col2 = st.columns([5, 2])
    
    with blk_col1:
        if not df_blocks.empty:
            df_blocks.insert(0, 'Row #', range(1, 1 + len(df_blocks)))
            s_col1, s_col2 = st.columns([2, 1])
            with s_col1:
                query_text = st.text_input("🔍 Search Blocklist...", key="block_search").strip().lower()
            with s_col2:
                filter_col = st.selectbox("Filter Field", ["Any Field"] + list(df_blocks.columns), key="block_filter")

            filtered_df = df_blocks.copy()
            if query_text:
                if filter_col == "Any Field":
                    mask = filtered_df.astype(str).apply(lambda x: x.str.lower().str.contains(query_text, na=False, regex=False).any(), axis=1)
                    filtered_df = filtered_df[mask]
                else:
                    filtered_df = filtered_df[filtered_df[filter_col].astype(str).str.lower().str.contains(query_text, na=False, regex=False)]

            st.dataframe(filtered_df, use_container_width=True, hide_index=True)
        else:
            st.info("Blocklist is empty. Please use the bulk upload tool on the right to import indicators.")
            filtered_df = df_blocks

    with blk_col2:
        st.subheader("Indicator Actions")
        
        # 2. Only show export if data exists
        if not df_blocks.empty:
            csv_blocks = filtered_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Export Blocklist CSV",
                data=csv_blocks,
                file_name="threat_blocklist.csv",
                mime="text/csv",
                use_container_width=True
            )
        
        # 3. ALWAYS show the Import uploader
        uploaded_blocks = st.file_uploader("Bulk Upload Blocklist (.csv)", type=["csv"], key="blk_csv")
        if uploaded_blocks is not None and st.button("Process Blocklist CSV", use_container_width=True):
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