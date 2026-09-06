import streamlit as st
import folium
from streamlit_folium import st_folium
from logic.export import generate_case_pdf  # <-- 1. Add this import

def render_workbench():
    st.markdown("<h2>Active Evidence Workbench</h2>", unsafe_allow_html=True)
    st.caption("Deep-dive telemetry for currently ingested cases.")
    
    if not st.session_state.analyzed_store:
        st.info("No active cases in session. Please upload a file via the Upload & Ingest page.")
        return

    selected_case = st.selectbox("Select Active Case:", list(st.session_state.analyzed_store.keys()))
    data = st.session_state.analyzed_store[selected_case]
    
    # --- 2. ADD THE PDF DOWNLOAD BUTTON BLOCK HERE ---
    col1, col2 = st.columns([3, 1])
    with col1:
        st.write(f"**Investigating:** `{data['file_name']}` | **SHA256:** `{data['hash']}`")
    with col2:
        pdf_bytes = generate_case_pdf(data)
        st.download_button(
            label="📄 Download PDF Report",
            data=pdf_bytes,
            file_name=f"{selected_case}_Forensic_Report.pdf",
            mime="application/pdf",
            use_container_width=True
        )
    # ------------------------------------------------

    t1, t2, t3, t4 = st.tabs(["Headers & Body", "Authentication", "Geo Map", "Heuristics"])

        
    with t1:
        st.json(data["decomp"]["headers"])
        st.text_area("Plain Text Body Extract", data["decomp"]["body_preview"], height=200, disabled=True)
        
    with t2:
        st.metric("SPF Verification", data["auth"]["spf"]["status"])
        st.metric("DMARC Enforcement", data["auth"]["dmarc"]["policy"])
        st.json(data["auth"])
        
    with t3:
        st.write(f"**Origin IP:** `{data['geo'].get('ip')}` | **Country:** {data['geo'].get('country')}")
        if data["geo"].get("lat") and data["geo"].get("lon"):
            # Initialize map centered on the IP's coordinates
            m = folium.Map(location=[data["geo"]["lat"], data["geo"]["lon"]], zoom_start=3)
            folium.Marker(
                [data["geo"]["lat"], data["geo"]["lon"]], 
                popup=f"Origin: {data['geo'].get('ip')}",
                icon=folium.Icon(color="red", icon="info-sign")
            ).add_to(m)
            st_folium(m, width=800, height=400)
        else:
            st.warning("Valid geographical coordinates not found for this IP.")
            
    with t4:
        st.metric("Heuristic Risk Penalty", f"+ {data['heur']['score']} points")
        st.write("**Suspicious URLs Extracted:**")
        st.code("\n".join(data["heur"]["urls"]) if data["heur"]["urls"] else "None detected", language="text")
        st.write("**Social Engineering Trigger Keywords:**")
        st.code(", ".join(data["heur"]["keywords"]) if data["heur"]["keywords"] else "None detected", language="text")