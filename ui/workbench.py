import streamlit as st
import folium
from streamlit_folium import st_folium
from logic.export import generate_case_pdf

def render_workbench():
    st.markdown("<h2>Active Evidence Workbench</h2>", unsafe_allow_html=True)
    st.caption("Deep-dive telemetry for currently ingested cases.")
    
    if not st.session_state.analyzed_store:
        st.info("No active cases in session. Please upload a file via the Upload & Ingest page.")
        return

    # --- UPDATED SELECTION LOGIC FOR REDIRECT ---
    case_keys = list(st.session_state.analyzed_store.keys())
    
    default_idx = 0
    if st.session_state.get("selected_case") in case_keys:
        default_idx = case_keys.index(st.session_state.selected_case)

    selected_case = st.selectbox(
        "Select Active Case:", 
        case_keys, 
        index=default_idx
    )
    st.session_state.selected_case = selected_case
    data = st.session_state.analyzed_store[selected_case]
    # ---------------------------------------------
    
    # --- PDF DOWNLOAD BUTTON BLOCK ---
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

    t1, t2, t3, t4 = st.tabs(["Headers & Body", "Authentication", "Geo Map", "Threat Intel"])

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
        # Load data
        heur_data = data.get("heur", {})
        intel_data = data.get("intel", {})
        
        st.metric("Total Heuristic & Intel Penalty", f"+ {heur_data.get('score', 0) + intel_data.get('penalty', 0)} points")
        
        st.divider()
        st.subheader("🛡️ Internal Ledger Cross-Reference")
        
        # Display Spoofing Alert
        if intel_data.get("is_spoofing"):
            st.error(f"🚨 **VIP SPOOFING DETECTED:** The sender is attempting to impersonate internal employee: **{intel_data.get('spoofed_user')}**")
        else:
            st.success("✅ No internal executive spoofing detected.")
            
        # Display Blocklist Hits
        if intel_data.get("blocklist_hits"):
            st.error("🚨 **BLOCKLIST HITS DETECTED:**")
            for hit in intel_data["blocklist_hits"]:
                st.write(f"- {hit}")
        else:
            st.success("✅ No indicators matched internal blocklist.")
            
        st.divider()
        st.subheader("🎣 General Phishing Heuristics")
        
        st.write("**Suspicious URLs Extracted:**")
        st.code("\n".join(heur_data.get("urls", [])) if heur_data.get("urls") else "None detected", language="text")
        st.write("**Social Engineering Trigger Keywords:**")
        st.code(", ".join(heur_data.get("keywords", [])) if heur_data.get("keywords") else "None detected", language="text")


    st.divider()
    tz_mode = "Local System Time" if str(st.session_state.get("tz_pref")).startswith("Local") else "UTC (Coordinated Universal Time)"
    st.caption(f"🕒 **Timezone Mode:** All forensic timelines and extracted headers are currently displayed in **{tz_mode}**.")