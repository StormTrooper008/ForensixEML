import streamlit as st
import folium
from streamlit_folium import st_folium
from logic.export import generate_case_pdf
import pandas as pd

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
        index=default_idx,
        # --- NEW: Formats the dropdown to show "Filename | Risk Score (Case ID)" ---
        format_func=lambda cid: f"{st.session_state.analyzed_store[cid]['file_name']} | Risk: {st.session_state.analyzed_store[cid]['risk_score']} ({cid})"
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

    # --- NEW: AI EXECUTIVE BRIEFING ---
    ai_summary_text = data.get("ai_insight", "No summary available for this case.")
    st.info(f"**🧠 AI Executive Summary:**\n\n{ai_summary_text}")
    st.divider()
    # ----------------------------------

    t1, t2, t3, t4, t5 = st.tabs(["Headers & Body", "Authentication", "Geo Map", "Threat Intel", "📎 Attachments"])

    with t1:
        st.json(data["decomp"]["headers"])
        
        st.divider()
        st.subheader("🎯 Target Distribution (Blast Radius)")
        recipient_list = data["decomp"].get("recipients", [])
        if recipient_list:
            st.write(f"**Total Identified Targets:** `{len(recipient_list)}`")
            st.dataframe(
                pd.DataFrame(recipient_list),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No standard To/Cc/Bcc recipient headers found in message envelope.")
        st.divider()
        
        toggle_key = f"expand_body_{selected_case}"
        if toggle_key not in st.session_state:
            st.session_state[toggle_key] = False
            
        if not st.session_state[toggle_key]:
            st.text_area("Plain Text Body Extract (Preview)", data["decomp"].get("body_preview", "No text available."), height=150, disabled=True)
            if st.button("🔽 Expand Full Text", key=f"btn_expand_{selected_case}"):
                st.session_state[toggle_key] = True
                st.rerun()
        else:
            full_text = data["decomp"].get("body_full", data["decomp"].get("body_preview", "No full text available."))
            st.text_area("Plain Text Body Extract (Full)", full_text, height=400, disabled=False)
            if st.button("🔼 Minimize to Preview", key=f"btn_min_{selected_case}"):
                st.session_state[toggle_key] = False
                st.rerun()
        
    with t2:
        auth_c1, auth_c2, auth_c3 = st.columns(3)
        with auth_c1:
            st.metric("SPF Verification", data["auth"]["spf"]["status"])
        with auth_c2:
            st.metric("DKIM Signature", data["auth"].get("dkim", {}).get("status", "UNCHECKED"))
        with auth_c3:
            st.metric("DMARC Enforcement", data["auth"]["dmarc"]["policy"])
            
        st.divider()
        st.json(data["auth"])
        
    with t3:
        origin_ip = data["geo"].get("ip", "Unknown")
        origin_country = data["geo"].get("country", "Unknown")
        provider_name = data["geo"].get("org") or data["geo"].get("isp") or data["geo"].get("as") or "Local / Private Infrastructure"
        asn_record = data["geo"].get("as", "N/A")

        st.write(f"**Origin IP:** `{origin_ip}` | **Country:** {origin_country}")
        st.info(f"🏢 **Originated From Infrastructure:** `{provider_name}` | **ASN:** `{asn_record}`")

        route_coords = []
        has_origin_coords = bool(data["geo"].get("lat") and data["geo"].get("lon"))

        hop_markers = []
        for hop_idx, hop in enumerate(data["decomp"].get("hops", [])):
            for ip_data in hop.get("extracted_ips", []):
                geo = ip_data.get("geo", {})
                if geo.get("lat") and geo.get("lon"):
                    coords = [geo["lat"], geo["lon"]]
                    route_coords.append(coords)
                    hop_provider = geo.get("org") or geo.get("isp") or "Unknown Provider"
                    hop_markers.append({
                        "coords": coords,
                        "label": f"Hop {hop_idx + 1}: {geo.get('ip', 'Unknown')} ({geo.get('country', 'Unknown')}) | {hop_provider}"
                    })

        if has_origin_coords:
            origin_coords = [data["geo"]["lat"], data["geo"]["lon"]]
            route_coords.append(origin_coords)
        else:
            st.warning(f"⚠️ No public geographic coordinates resolved for Origin IP `{origin_ip}`.")

        if route_coords:
            map_center = [data["geo"]["lat"], data["geo"]["lon"]] if has_origin_coords else route_coords[0]
            m = folium.Map(location=map_center, zoom_start=2)

            for marker in hop_markers:
                folium.Marker(marker["coords"], popup=marker["label"], icon=folium.Icon(color="blue", icon="cloud")).add_to(m)

            if has_origin_coords:
                folium.Marker([data["geo"]["lat"], data["geo"]["lon"]], popup=f"Origin: {origin_ip} ({origin_country}) | {provider_name}", icon=folium.Icon(color="red", icon="info-sign")).add_to(m)

            if len(route_coords) > 1:
                folium.PolyLine(route_coords, color="red", weight=2.5, opacity=0.8, dash_array="5, 5").add_to(m)

            st_folium(m, width=800, height=400)
        else:
            st.warning("Valid geographical coordinates not found for this IP or intermediate mail hops.")

    with t4:
        heur_data = data.get("heur", {})
        intel_data = data.get("intel", {})
        st.metric("Total Heuristic & Intel Penalty", f"+ {heur_data.get('score', 0) + intel_data.get('penalty', 0)} points")
        
        st.divider()
        st.subheader("🛡️ Internal Ledger Cross-Reference")
        if intel_data.get("is_spoofing"):
            st.error(f"🚨 **VIP SPOOFING DETECTED:** The sender is attempting to impersonate internal employee: **{intel_data.get('spoofed_user')}**")
        else:
            st.success("✅ No internal executive spoofing detected.")
            
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
        st.write("**🎣 Bait & Switch Link Mismatches:**")
        mismatches = heur_data.get("link_mismatches", [])
        if mismatches:
            for mismatch in mismatches:
                st.error(f"🚨 **Deceptive Link!**\n\n**Visible Text:** `{mismatch['claimed']}`\n\n**Hidden Destination:** `{mismatch['actual']}`")
        else:
            st.success("✅ No deceptive hyperlink mismatches detected.")

    with t5:
        # --- NEW: Attachment Forensics Tab ---
        st.subheader("📦 MIME Payload Analysis")
        attachments = data["decomp"].get("attachments", [])
        
        if not attachments:
            st.info("No attachments found in this message.")
        else:
            for att in attachments:
                if att.get("is_risky"):
                    st.error(f"🚨 **HIGH RISK PAYLOAD DETECTED**")
                else:
                    st.success("✅ Standard Attachment")
                    
                st.write(f"**Filename:** `{att.get('filename')}`")
                st.write(f"**Size:** `{att.get('size_kb')} KB` | **Type:** `{att.get('content_type')}`")
                st.write(f"**SHA256 Fingerprint:** `{att.get('sha256')}`")
                st.divider()

    st.divider()
    tz_mode = "Local System Time" if str(st.session_state.get("tz_pref")).startswith("Local") else "UTC (Coordinated Universal Time)"
    st.caption(f"🕒 **Timezone Mode:** All forensic timelines and extracted headers are currently displayed in **{tz_mode}**.")