import hashlib
import json
import os
import folium
import pandas as pd
import streamlit as st
from streamlit_folium import st_folium

from logic.parser import parse_step1_headers
from logic.auth import run_protocol_checks
from logic.enrichment import get_ip_geolocation, enrich_hop_chain

# Page Configuration
st.set_page_config(
    page_title="Forensic Email Threat Analyzer",
    page_icon="💾",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling
st.markdown(
    """
    <style>
        .metric-card {
            background-color: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 18px 22px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.03);
        }
        .metric-title {
            color: #64748b;
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 6px;
        }
        .metric-value {
            color: #0f172a;
            font-size: 26px;
            font-weight: 700;
        }
        .hero-banner {
            background: linear-gradient(135deg, #172554, #1e3a8a);
            border-radius: 14px;
            padding: 24px;
            color: #ffffff;
            margin-bottom: 24px;
        }
        .hero-banner h2 {
            color: #ffffff;
            margin-bottom: 6px;
        }
        .hero-banner p {
            color: #cbd5e1;
            font-size: 15px;
            margin-bottom: 0px;
        }
    </style>
""",
    unsafe_allow_html=True,
)

# Session State History
if "history" not in st.session_state:
    st.session_state.history = [
        {
            "Case ID": "CASE-1001",
            "File Name": "mock_sample_1.eml",
            "Email": "security@bank-alert.com",
            "Subject": "Urgent Account Verification",
            "Origin IP": "185.220.101.5",
            "Origin Country": "Russia",
            "SPF": "FAIL",
            "DMARC": "REJECT",
            "Risk Score": 85,
            "Status": "🔴 Malicious",
        }
    ]

if "analyzed_store" not in st.session_state:
    st.session_state.analyzed_store = {}

# 1. Sidebar Navigation
with st.sidebar:
    st.markdown("## 💾 **Forensic Email Analyzer**")
    st.caption("SIH Problem Statement 26106 | Forensic Triage")
    st.divider()

    nav_choice = st.radio(
        "Navigation",
        [
            "🏠 Dashboard",
            "📧 Email Analysis",
            "🌍 Geolocation & Map",
            "🔐 Protocol & Auth",
            "🔍 Forensic Relays",
            "📊 Raw Intelligence",
        ],
        index=0,
    )

    st.divider()
    st.markdown("👤 **Security Analyst**")
    st.caption("Role: Incident Responder | Tier 2")

# 2. Hero Header & Overview Metrics
st.markdown(
    """
    <div class="hero-banner">
        <h2>Threat Detection & Investigation Dashboard</h2>
        <p>Forensic header parsing, protocol authentication (SPF/DMARC), and GeoIP origin tracking</p>
    </div>
""",
    unsafe_allow_html=True,
)

total_emails = len(st.session_state.history)
threats_detected = sum(1 for item in st.session_state.history if item["Risk Score"] >= 50)
high_risk = sum(1 for item in st.session_state.history if item["Risk Score"] >= 75)
safe_emails = sum(1 for item in st.session_state.history if item["Risk Score"] < 50)

col1, col2, col3, col4 = st.columns(4)
col1.markdown(
    f"""<div class="metric-card"><div class="metric-title">📧 Total Tracked</div><div class="metric-value">{total_emails}</div></div>""",
    unsafe_allow_html=True,
)
col2.markdown(
    f"""<div class="metric-card"><div class="metric-title">🚨 Threats Detected</div><div class="metric-value">{threats_detected}</div></div>""",
    unsafe_allow_html=True,
)
col3.markdown(
    f"""<div class="metric-card"><div class="metric-title">⚠️ High Risk</div><div class="metric-value">{high_risk}</div></div>""",
    unsafe_allow_html=True,
)
col4.markdown(
    f"""<div class="metric-card"><div class="metric-title">🛡️ Safe Emails</div><div class="metric-value">{safe_emails}</div></div>""",
    unsafe_allow_html=True,
)

st.write("")

# 3. Batch Upload & Ingestion Panel
st.subheader("🔍 Ingest & Analyze Messages")

with st.expander("📁 Batch File Upload Panel", expanded=True):
    uploaded_files = st.file_uploader(
        "Upload one or more RFC 822 email files (.eml)",
        type=["eml"],
        accept_multiple_files=True,
    )
    confirm_button = st.button("Confirm Upload", type="primary", use_container_width=True)

if confirm_button:
    if uploaded_files:
        ingested_count = 0
        for upl_file in uploaded_files:
            file_bytes = upl_file.read()
            file_sha256 = hashlib.sha256(file_bytes).hexdigest()

            if any(file_sha256 == item.get("sha256") for item in st.session_state.analyzed_store.values()):
                continue

            case_id = f"CASE-{1000 + len(st.session_state.analyzed_store) + 1}"

            # Step 1: Decomposition
            decomp = parse_step1_headers(file_bytes)

            # Step 2: Protocol verification
            sender_header = decomp["headers"]["From"]
            origin_ip = decomp["origin_candidate"]["ip"]
            auth = run_protocol_checks(sender_header, origin_ip)

            # Step 3: Threat Enrichment & Geolocation
            origin_geo = get_ip_geolocation(origin_ip)
            enriched_hops = enrich_hop_chain(decomp["hops"])
            decomp["hops"] = enriched_hops

            # Balanced Forensic Risk Calculation
            calculated_risk = 10
            if auth["spf"]["status"] == "FAIL":
                calculated_risk += 35
            elif auth["spf"]["status"] == "NEUTRAL":
                calculated_risk += 10

            if auth["dmarc"]["policy"] in ["NONE", "MISSING"]:
                calculated_risk += 10

            if origin_geo.get("threat_score", 0) > 40:
                calculated_risk += 35

            status_label = (
                "🔴 Malicious"
                if calculated_risk >= 70
                else ("🟡 Suspicious" if calculated_risk >= 40 else "🟢 Safe")
            )

            # Store Complete Forensic Record
            st.session_state.analyzed_store[case_id] = {
                "case_id": case_id,
                "file_name": upl_file.name,
                "sha256": file_sha256,
                "decomposition": decomp,
                "authentication": auth,
                "geo": origin_geo,
                "risk_score": calculated_risk,
                "status": status_label,
            }

            st.session_state.history.insert(
                0,
                {
                    "Case ID": case_id,
                    "File Name": upl_file.name,
                    "Email": sender_header,
                    "Subject": decomp["headers"]["Subject"],
                    "Origin IP": origin_ip,
                    "Origin Country": origin_geo.get("country", "Unknown"),
                    "SPF": auth["spf"]["status"],
                    "DMARC": auth["dmarc"]["policy"],
                    "Risk Score": calculated_risk,
                    "Status": status_label,
                },
            )
            ingested_count += 1

        if ingested_count > 0:
            st.success(f"Successfully analyzed {ingested_count} file(s).")
            st.rerun()
    else:
        st.warning("Please upload at least one .eml file.")

# 4. Evidence Selector
active_case_data = None
if st.session_state.analyzed_store:
    st.divider()
    st.subheader("🎯 Active Evidence Inspector")

    def format_case_label(cid: str) -> str:
        record = st.session_state.analyzed_store[cid]
        fname = record["file_name"]
        subj = record["decomposition"]["headers"]["Subject"]
        sender = record["decomposition"]["headers"]["From"]
        return f"[{cid}] [{fname}] \"{subj[:30]}...\" — from: {sender[:35]}"

    selected_cid = st.selectbox(
        "Select email to inspect:",
        options=list(st.session_state.analyzed_store.keys()),
        format_func=format_case_label,
    )
    active_case_data = st.session_state.analyzed_store[selected_cid]

# 5. Render Selected Email Data
if active_case_data:
    headers = active_case_data["decomposition"]["headers"]
    origin = active_case_data["decomposition"]["origin_candidate"]
    auth_results = active_case_data["authentication"]
    geo_data = active_case_data.get("geo", {})

    # File Badges
    m1, m2, m3 = st.columns(3)
    m1.info(f"📁 **File:** `{active_case_data['file_name']}`")
    m2.info(f"🆔 **Case:** `{active_case_data['case_id']}`")
    m3.info(f"🔒 **SHA-256:** `{active_case_data['sha256'][:16]}...`")

    if nav_choice in ["🏠 Dashboard", "📧 Email Analysis"]:
        st.write("---")
        st.subheader("Sender & Origin Intelligence")
        left_col, right_col = st.columns([3, 2])

        with left_col:
            st.write(f"**Subject:** {headers['Subject']}")
            st.write(f"**From:** `{headers['From']}`")
            st.write(f"**Return-Path:** `{headers['Return-Path']}`")
            st.write(f"**Reply-To:** `{headers['Reply-To']}`")
            st.write(f"**Date:** {headers['Date']}")

        with right_col:
            st.metric(label="Detected Origin IP", value=origin["ip"])
            st.write(f"**Country / City:** {geo_data.get('country', 'Unknown')} ({geo_data.get('city', 'Unknown')})")
            st.write(f"**ISP / ASN:** `{geo_data.get('isp', 'Unknown')}`")
            st.write(f"**Scope:** `{origin['scope']}`")

        st.markdown("#### Extracted Plain Text Body")
        st.text_area(
            "Decoded Body",
            active_case_data["decomposition"]["body_preview"],
            height=120,
            disabled=True,
        )

    if nav_choice in ["🏠 Dashboard", "🌍 Geolocation & Map"]:
        st.write("---")
        st.subheader("Interactive Hop Geolocation Map")

        # Collect all points with coordinates
        route_points = []
        for hop in active_case_data["decomposition"]["hops"]:
            for ip_obj in hop.get("extracted_ips", []):
                g = ip_obj.get("geo", {})
                if g.get("is_public") and g.get("lat") and g.get("lon"):
                    route_points.append({
                        "hop": hop["hop_number"],
                        "ip": g["ip"],
                        "country": g["country"],
                        "city": g["city"],
                        "lat": g["lat"],
                        "lon": g["lon"],
                        "isp": g["isp"]
                    })

        if route_points:
            # Center on first point
            start_coord = [route_points[0]["lat"], route_points[0]["lon"]]
            m = folium.Map(location=start_coord, zoom_start=2, tiles="CartoDB positron")

            coords_for_line = []
            for pt in route_points:
                coords = [pt["lat"], pt["lon"]]
                coords_for_line.append(coords)
                popup_text = f"Hop #{pt['hop']}<br>IP: {pt['ip']}<br>{pt['city']}, {pt['country']}<br>ISP: {pt['isp']}"
                folium.Marker(
                    location=coords,
                    tooltip=f"Hop #{pt['hop']}: {pt['ip']}",
                    popup=folium.Popup(popup_text, max_width=300),
                    icon=folium.Icon(color="red" if pt["hop"] == 1 else "blue", icon="envelope"),
                ).add_to(m)

            if len(coords_for_line) > 1:
                folium.PolyLine(coords_for_line, color="crimson", weight=3, opacity=0.8, dash_array="5, 10").add_to(m)

            st_folium(m, width=1100, height=450)
        else:
            st.info("No public routable IPs with geographic coordinates were present in this email's hop chain.")

    if nav_choice in ["🏠 Dashboard", "🔐 Protocol & Auth"]:
        st.write("---")
        st.subheader("DNS Protocol Authentication")
        auth_c1, auth_c2, auth_c3 = st.columns(3)
        auth_c1.metric(label="Sender Domain", value=auth_results["domain"] or "None")
        auth_c2.metric(label="SPF Status", value=auth_results["spf"]["status"])
        auth_c3.metric(label="DMARC Policy", value=auth_results["dmarc"]["policy"])

        with st.expander("Inspect Raw DNS Authentication Records"):
            st.write("**SPF TXT Record:**")
            st.code(auth_results["spf"]["raw_spf"] or "No SPF record found.", language="text")
            st.write("**DMARC TXT Record:**")
            st.code(auth_results["dmarc"]["raw_dmarc"] or "No DMARC record found.", language="text")

    if nav_choice in ["🏠 Dashboard", "🔍 Forensic Relays"]:
        st.write("---")
        st.subheader("Chronological Hop Route (Received: Chain)")
        for hop in active_case_data["decomposition"]["hops"]:
            ip_list = [ip["ip"] for ip in hop["extracted_ips"]]
            with st.expander(f"Hop #{hop['hop_number']} — Extracted IPs: {ip_list if ip_list else 'None'}"):
                st.code(hop["raw_text"], language="text")

    if nav_choice == "📊 Raw Intelligence":
        st.write("---")
        st.subheader("Forensic JSON Telemetry")
        st.json(active_case_data)

# 6. Global History Table
st.divider()
st.subheader("Recent Email Investigations")
history_df = pd.DataFrame(st.session_state.history)
st.dataframe(history_df, use_container_width=True, hide_index=True)