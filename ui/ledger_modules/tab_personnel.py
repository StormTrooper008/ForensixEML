import streamlit as st
import pandas as pd

def render_tab_personnel(conn):
    st.markdown("### 👥 Personnel Roster")
    if str(st.session_state.get("tz_pref")).startswith("Local"):
        query = """SELECT org_id, full_name, email, designation, notes, 
                   datetime(timestamp_added, 'localtime') as timestamp_added, 
                   datetime(last_modified, 'localtime') as last_modified 
                   FROM personnel ORDER BY full_name ASC"""
    else:
        query = """SELECT org_id, full_name, email, designation, notes, 
                   timestamp_added, last_modified 
                   FROM personnel ORDER BY full_name ASC"""
                   
    df_pers = pd.read_sql_query(query, conn)
    
    # 1. Force the columns to ALWAYS render
    per_col1, per_col2 = st.columns([5, 2])
    
    with per_col1:
        if not df_pers.empty:
            df_pers.insert(0, 'Row #', range(1, 1 + len(df_pers)))
            s_col1, s_col2 = st.columns([2, 1])
            with s_col1:
                query_text = st.text_input("🔍 Search Personnel...", key="pers_search").strip().lower()
            with s_col2:
                filter_col = st.selectbox("Filter Field", ["Any Field"] + list(df_pers.columns), key="pers_filter")

            filtered_df = df_pers.copy()
            if query_text:
                if filter_col == "Any Field":
                    mask = filtered_df.astype(str).apply(lambda x: x.str.lower().str.contains(query_text, na=False, regex=False).any(), axis=1)
                    filtered_df = filtered_df[mask]
                else:
                    filtered_df = filtered_df[filtered_df[filter_col].astype(str).str.lower().str.contains(query_text, na=False, regex=False)]

            st.dataframe(filtered_df, use_container_width=True, hide_index=True)
        else:
            st.info("No personnel records found. Please use the bulk upload tool on the right to import your roster.")
            filtered_df = df_pers # Failsafe for empty state

    with per_col2:
        st.subheader("Roster Actions")
        
        # 2. Only show the Export button if there is actually data to export
        if not df_pers.empty:
            csv_pers = filtered_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Export Roster CSV",
                data=csv_pers,
                file_name="personnel_roster.csv",
                mime="text/csv",
                use_container_width=True
            )
        
        # 3. ALWAYS show the Import uploader
        uploaded_pers = st.file_uploader("Bulk Upload Personnel (.csv)", type=["csv"], key="per_csv")
        if uploaded_pers is not None and st.button("Process Roster CSV", use_container_width=True):
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