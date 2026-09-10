# --- ui/workbench.py ---
import streamlit as st
import json
import sqlite3
import networkx as nx
from streamlit_agraph import agraph, Node, Edge, Config
import folium
from streamlit_folium import st_folium
from logic.export import generate_case_pdf
import pandas as pd
from logic.database import get_db_connection

def fetch_recent_cases(limit=50):
    """Fetches the latest ingested cases directly from the database for the live feed."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row if hasattr(sqlite3, 'Row') else conn.row_factory
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM cases ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(r) for r in cursor.fetchall()]
    except Exception as e:
        st.error(f"Database error: {e}")
        return []
    finally:
        conn.close()

def render_workbench():
    st.markdown("<h2>Active Evidence Workbench</h2>", unsafe_allow_html=True)
    st.caption("Deep-dive telemetry for currently ingested cases. Live feed updates from the database.")
    
    col_btn1, col_btn2 = st.columns([1, 5])
    with col_btn1:
        if st.button("🔄 Refresh Live Feed", use_container_width=True):
            st.rerun()

    cases = fetch_recent_cases()
    if not cases:
        st.info("📭 Inbox is empty. Start the Auto-Ingestion Daemon or upload files to see data here.")
        return

    # --- INTELLIGENT CASE SELECTION & RETENTION ---
    active_case_id = st.session_state.get("selected_case")
    
    # If the selected case isn't in our current list, check if it exists in the full DB 
    # (in case the background daemon pushed it past the top 50 limit)
    case_ids = [c['case_id'] for c in cases]
    
    if active_case_id and active_case_id not in case_ids:
        # Fetch that specific case directly so it doesn't get lost
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row if hasattr(sqlite3, 'Row') else conn.row_factory
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cases WHERE case_id = ?", (active_case_id,))
        specific_case = cursor.fetchone()
        conn.close()
        
        if specific_case:
            # Prepend it to our cases list so it renders in the UI
            cases.insert(0, dict(specific_case))
            case_ids.insert(0, active_case_id)

    # Final fallback to newest if nothing is selected at all
    if not active_case_id or active_case_id not in case_ids:
        active_case_id = cases[0]['case_id']
        st.session_state.selected_case = active_case_id

    # --- Dual Pane Layout (1:2.2 Ratio) ---
    col_list, col_details = st.columns([1, 2.2])
    
    # -----------------------------------------
    # LEFT PANE: The Inbox List (Scrollable)
    # -----------------------------------------
    with col_list:
        st.markdown("#### 📥 Live Traffic")
        with st.container(height=800):
            for c in cases:
                if "Malicious" in c['status']:
                    status_color, icon = "red", "🔴"
                elif "Suspicious" in c['status']:
                    status_color, icon = "orange", "🟡"
                else:
                    status_color, icon = "green", "🟢"
                
                short_sender = (c['sender'][:25] + '...') if len(c['sender']) > 25 else c['sender']
                short_subject = (c['subject'][:30] + '...') if len(c['subject']) > 30 else c['subject']
                
                is_currently_selected = (c['case_id'] == active_case_id)
                
                # Render a container with a visual border highlight if it's the active case
                with st.container(border=True):
                    if is_currently_selected:
                        st.markdown(f"👉 **`{c['case_id']}`** (Active)")
                    st.markdown(f"**{short_sender}**")
                    st.markdown(f"*{short_subject}*")
                    
                    bottom_left, bottom_right = st.columns([1.5, 1])
                    with bottom_left:
                        st.markdown(f":{status_color}[**{icon} {c['status']}**] ({c['risk_score']}%)")
                    with bottom_right:
                        btn_label = "Viewing" if is_currently_selected else "View"
                        btn_type = "primary" if is_currently_selected else "secondary"
                        if st.button(btn_label, key=f"btn_{c['case_id']}", type=btn_type, use_container_width=True):
                            st.session_state.selected_case = c['case_id']
                            st.rerun()

    # -----------------------------------------
    # RIGHT PANE: The Forensic Dossier
    # -----------------------------------------
    with col_details:
        selected = next((c for c in cases if c['case_id'] == active_case_id), None)
        
        if selected:
            telemetry = json.loads(selected['telemetry']) if selected['telemetry'] else {}
            data = {
                "case_id": selected["case_id"], # <-- Added this so it's not UNKNOWN
                "file_name": selected["file_name"],
                "hash": selected["sha256"],
                "risk_score": selected["risk_score"],
                "status": selected["status"],
                "ai_insight": selected["ai_notes"],
                "decomp": telemetry.get("decomp", {}),
                "auth": telemetry.get("auth", {}),
                "geo": telemetry.get("geo", {}),
                "heur": telemetry.get("heur", {}),
                "intel": telemetry.get("intel", {})
            }
            
            # --- PDF EXPORT & LOCAL PATH BLOCK ---
            col1, col2 = st.columns([2.5, 1.5])
            with col1:
                st.write(f"**Investigating:** `{data['file_name']}` | **SHA256:** `{data['hash']}`")
            with col2:
                if st.button("📄 Generate Forensic Report", key=f"gen_pdf_{active_case_id}", use_container_width=True):
                    saved_path = generate_case_pdf(data)
                    if saved_path:
                        st.session_state[f"last_report_{active_case_id}"] = saved_path
                        st.toast("Report saved successfully to local disk!", icon="📁")
                    else:
                        st.error("Failed to generate local report.")

            # Display path popup cleanly right under the header
            report_key = f"last_report_{active_case_id}"
            if st.session_state.get(report_key):
                st.success("✨ Immutable Forensic PDF Report Generated & Saved Locally:")
                st.code(st.session_state[report_key], language="text")

            st.divider()
            
            # --- THE 6 TABS ---
            t1, t2, t3, t4, t5, t6 = st.tabs(["Headers & Body", "Authentication", "Geo Map", "Threat Intel", "📎 Attachments", "🛤️ Trace Map"])

            with t1:
                st.json(data["decomp"].get("headers", {}))
                st.divider()
                st.subheader("🎯 Target Distribution (Blast Radius)")
                recipient_list = data["decomp"].get("recipients", [])
                if recipient_list:
                    st.write(f"**Total Identified Targets:** `{len(recipient_list)}`")
                    st.dataframe(pd.DataFrame(recipient_list), use_container_width=True, hide_index=True)
                else:
                    st.info("No standard To/Cc/Bcc recipient headers found in message envelope.")
                st.divider()
                
                toggle_key = f"expand_body_{active_case_id}"
                if toggle_key not in st.session_state:
                    st.session_state[toggle_key] = False
                    
                if not st.session_state[toggle_key]:
                    st.text_area("Plain Text Body Extract (Preview)", data["decomp"].get("body_preview", "No text available."), height=150, disabled=True)
                    if st.button("🔽 Expand Full Text", key=f"btn_expand_{active_case_id}"):
                        st.session_state[toggle_key] = True
                        st.rerun()
                else:
                    full_text = data["decomp"].get("body_full", data["decomp"].get("body_preview", "No full text available."))
                    st.text_area("Plain Text Body Extract (Full)", full_text, height=400, disabled=False)
                    if st.button("🔼 Minimize to Preview", key=f"btn_min_{active_case_id}"):
                        st.session_state[toggle_key] = False
                        st.rerun()
                
            with t2:
                auth_c1, auth_c2, auth_c3 = st.columns(3)
                with auth_c1:
                    st.metric("SPF Verification", data["auth"].get("spf", {}).get("status", "UNCHECKED"))
                with auth_c2:
                    st.metric("DKIM Signature", data["auth"].get("dkim", {}).get("status", "UNCHECKED"))
                with auth_c3:
                    st.metric("DMARC Enforcement", data["auth"].get("dmarc", {}).get("policy", "UNCHECKED"))
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
                st.subheader("🌍 Sender Domain Infrastructure (WHOIS/DNS)")
                whois_data = intel_data.get("domain_whois", {})
                
                if whois_data.get("status") == "OFFLINE":
                    st.warning("📴 **Air-Gapped Mode Active:** The system is currently offline. Live domain reconnaissance is paused to prevent data leaks.")
                elif whois_data and not whois_data.get("error"):
                    if whois_data.get("status") == "CACHED":
                        st.caption("💾 *Data loaded from local offline cache.*")
                    
                    col_w1, col_w2, col_w3 = st.columns(3)
                    col_w1.metric("Domain Age", f"{whois_data.get('age_days', 'Unknown')} days")
                    col_w2.metric("Registrar", str(whois_data.get("registrar", "Unknown"))[:20])
                    col_w3.metric("Creation Date", whois_data.get("creation_date", "Unknown"))
                    
                    if whois_data.get("is_suspicious"):
                        st.error("🚨 **WARNING:** This domain was registered very recently. Massive red flag for disposable phishing infrastructure.")
                        
                    with st.expander("View Raw DNS Records (A, MX, TXT)"):
                        st.write("**A Records (IPv4):**")
                        st.code("\n".join(whois_data.get("a_records", [])) or "None found", language="text")
                        st.write("**MX Records (Mail Exchange):**")
                        st.code("\n".join(whois_data.get("mx_records", [])) or "None found", language="text")
                        st.write("**TXT Records (SPF/DMARC/Verification):**")
                        st.code("\n".join(whois_data.get("txt_records", [])) or "None found", language="text")
                else:
                    st.info("No valid domain infrastructure data could be extracted.")

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

            with t6:
                st.subheader("🛤️ Visual Route Graph")
                st.caption("De-classified path from the message's Received headers: Sender → Relay Hops → Destination.")
                
                hops = data["decomp"].get("hops", [])
                if not hops:
                    st.info("No relay hops could be parsed from this email envelope.")
                else:
                    nodes = []
                    edges = []
                    
                    sender_email = data['decomp']['headers'].get('From', 'Unknown Sender')
                    nodes.append(Node(id="Start", label=sender_email[:30], color="#e06c75", shape="dot", size=25, title="Claimed Sender"))
                    
                    prev_node_id = "Start"
                    
                    for hop in hops:
                        delay = hop.get('delay_seconds', 0)
                        hop_num = hop['hop_number']
                        
                        if hop.get("extracted_ips"):
                            ip_data = hop["extracted_ips"][0]
                            ip_str = ip_data.get("ip")
                            scope = ip_data.get("classification", {}).get("scope", "UNKNOWN")
                            geo = ip_data.get("geo", {})
                            
                            node_id = f"Hop_{hop_num}"
                            
                            if scope == "RFC_1918_INTERNAL":
                                color = "#e5c07b" 
                                label = f"{ip_str}\n(Internal / VPN)"
                            else:
                                color = "#61afef"
                                provider = geo.get('org') or geo.get('isp') or "Unknown Provider"
                                label = f"{ip_str}\n{provider[:20]}"
                                
                            nodes.append(Node(
                                id=node_id, 
                                label=label, 
                                color=color, 
                                shape="dot", 
                                size=25, 
                                title=hop.get("raw_text", "No raw telemetry")
                            ))
                            
                            edge_label = f" {delay}s delay" if delay > 0 else " instant"
                            edges.append(Edge(source=prev_node_id, target=node_id, label=edge_label, color="#abb2bf"))
                            
                            prev_node_id = node_id
                            
                    nodes.append(Node(id="End", label="Your Organization", color="#98c379", shape="dot", size=25, title="Final Destination"))
                    edges.append(Edge(source=prev_node_id, target="End", color="#abb2bf"))
                    
                    config = Config(
                        width=800,
                        height=350,
                        directed=True,
                        physics=False,
                        hierarchical=True
                    )
                    config.layout = {
                        "hierarchical": {
                            "enabled": True, 
                            "direction": "LR", 
                            "sortMethod": "directed", 
                            "nodeSpacing": 200
                        }
                    }
                    
                    st.markdown("""
                    <div style="display:flex; gap:15px; flex-wrap:wrap; background-color:#1e222a; padding:10px; border-radius:6px; font-size:12px; margin-bottom:10px;">
                        <span style="color:#e06c75">● Claimed Sender</span> 
                        <span style="color:#61afef">● Public Relay Hop</span>
                        <span style="color:#e5c07b">● Internal / VPN Network</span> 
                        <span style="color:#98c379">● Destination</span>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    agraph(nodes=nodes, edges=edges, config=config)

                    with st.expander("Show Raw Hop Telemetry & Extracted Headers"):
                        for hop in hops:
                            st.markdown(f"**Hop {hop['hop_number']} Timestamp:** `{hop.get('timestamp', 'Unknown')}`")
                            st.code(hop.get("raw_text", ""), language="text")