import streamlit as st
import pandas as pd
from logic.database import get_db_connection

def render_dashboard():
    # 1. Hero Banner
    st.markdown(
        """
        <div class='hero-banner'>
            <h2>Threat Detection & Investigation Dashboard</h2>
            <p>Forensic header parsing, protocol authentication (SPF/DMARC), and GeoIP origin tracking</p>
        </div>
        """, 
        unsafe_allow_html=True
    )
    
    # 2. Fetch Database Metrics
    conn = get_db_connection()
    cases_df = pd.read_sql_query("SELECT * FROM cases ORDER BY timestamp DESC", conn)
    conn.close()

    total = len(cases_df)
    threats = len(cases_df[cases_df['risk_score'] >= 45]) if total > 0 else 0
    high_risk = len(cases_df[cases_df['risk_score'] >= 75]) if total > 0 else 0
    safe = len(cases_df[cases_df['risk_score'] < 45]) if total > 0 else 0
    
    # 3. Four-Column Custom Metric Cards
    col1, col2, col3, col4 = st.columns(4)
    
    col1.markdown(f"""
        <div class="metric-card">
            <div style="font-size: 14px; margin-bottom: 8px; opacity: 0.8;">📧 Total Tracked</div>
            <div style="font-size: 28px; font-weight: bold;">{total}</div>
        </div>
    """, unsafe_allow_html=True)
    
    col2.markdown(f"""
        <div class="metric-card">
            <div style="font-size: 14px; margin-bottom: 8px; opacity: 0.8;">🚨 Threats Detected</div>
            <div style="font-size: 28px; font-weight: bold;">{threats}</div>
        </div>
    """, unsafe_allow_html=True)
    
    col3.markdown(f"""
        <div class="metric-card">
            <div style="font-size: 14px; margin-bottom: 8px; opacity: 0.8;">⚠️ High Risk</div>
            <div style="font-size: 28px; font-weight: bold;">{high_risk}</div>
        </div>
    """, unsafe_allow_html=True)
    
    col4.markdown(f"""
        <div class="metric-card">
            <div style="font-size: 14px; margin-bottom: 8px; opacity: 0.8;">🛡️ Safe Emails</div>
            <div style="font-size: 28px; font-weight: bold;">{safe}</div>
        </div>
    """, unsafe_allow_html=True)

    st.write("") # Quick spacer
    st.subheader("Recent Threat Activity")
    
    if total > 0:
        st.dataframe(cases_df.head(10), use_container_width=True, hide_index=True)
    else:
        st.info("No cases ingested yet. Proceed to Upload & Ingest.")