import streamlit as st
import pandas as pd

def render_tab_blocklist(conn):
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