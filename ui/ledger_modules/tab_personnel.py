import streamlit as st
import pandas as pd

def render_tab_personnel(conn):
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