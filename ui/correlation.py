# ui/correlation.py
import streamlit as st
import networkx as nx
from logic.correlation import build_threat_graph

def render_graph_svg(G: nx.Graph, width=850, height=450) -> str:
    """Renders a self-contained SVG network visualization (100% Air-Gapped)."""
    if G.number_of_nodes() == 0:
        return "<p style='color:gray;'>Empty Graph</p>"

    # Compute coordinates using spring layout
    pos = nx.spring_layout(G, seed=42, k=1.2 / (G.number_of_nodes() ** 0.5 + 0.001))
    
    # Scale coordinates to SVG canvas viewBox
    padding = 60
    xs = [p[0] for p in pos.values()]
    ys = [p[1] for p in pos.values()]
    min_x, max_x = min(xs), max(xs) if max(xs) != min(xs) else min(xs) + 1
    min_y, max_y = min(ys), max(ys) if max(ys) != min(ys) else min(ys) + 1

    def scale_x(val):
        return padding + (val - min_x) / (max_x - min_x) * (width - 2 * padding)

    def scale_y(val):
        return padding + (val - min_y) / (max_y - min_y) * (height - 2 * padding)

    svg_lines = []
    svg_lines.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" style="background-color:#0e1117; border-radius:8px; width:100%;">')

    # Draw Edges
    for u, v in G.edges():
        x1, y1 = scale_x(pos[u][0]), scale_y(pos[u][1])
        x2, y2 = scale_x(pos[v][0]), scale_y(pos[v][1])
        svg_lines.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="#3b4252" stroke-width="1.8" stroke-opacity="0.8"/>')

    # Color Palette per Entity Type
    color_map = {
        "CASE": "#e06c75",       # Red
        "IP": "#61afef",         # Blue
        "DOMAIN": "#e5c07b",     # Gold
        "ASN": "#c678dd",        # Purple
        "ATTACHMENT": "#d19a66", # Orange
        "URL": "#98c379"         # Green
    }

    # Draw Nodes
    for node, data in G.nodes(data=True):
        nx_val, ny_val = scale_x(pos[node][0]), scale_y(pos[node][1])
        n_type = data.get("node_type", "CASE")
        fill = color_map.get(n_type, "#abb2bf")
        radius = 12 if n_type == "CASE" else 8
        label = data.get("label", node)[:16]

        svg_lines.append(f'<circle cx="{nx_val:.1f}" cy="{ny_val:.1f}" r="{radius}" fill="{fill}" stroke="#1e222a" stroke-width="2"><title>{data.get("label", node)} ({n_type})</title></circle>')
        svg_lines.append(f'<text x="{nx_val:.1f}" y="{ny_val + radius + 12:.1f}" fill="#d8dee9" font-size="10" font-family="sans-serif" text-anchor="middle">{label}</text>')

    svg_lines.append('</svg>')
    return "".join(svg_lines)

def render_correlation_view():
    st.markdown("<h2>🕸️ Threat Graph & Campaign Correlation</h2>", unsafe_allow_html=True)
    st.caption("Graph-based link analysis identifying shared threat infrastructure, persistent campaigns, and repeated actor fingerprints.")

    data = build_threat_graph()
    
    if data["total_cases"] == 0:
        st.info("No ingested cases found in the ledger. Ingest `.eml` files to populate the graph.")
        return

    # Metrics Summary Banner
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Tracked Cases", data["total_cases"])
    m2.metric("Linked Entities", data["total_nodes"])
    m3.metric("Correlation Edges", data["total_edges"])
    cluster_count = len([c for c in data["campaigns"] if c["is_cluster"]])
    m4.metric("Coordinated Campaigns", cluster_count)

    st.write("")
    
    # Legend
    st.markdown("""
    <div style="display:flex; gap:15px; flex-wrap:wrap; background-color:#1e222a; padding:10px; border-radius:6px; font-size:13px; margin-bottom:15px;">
        <span style="color:#e06c75">● Case</span>
        <span style="color:#61afef">● Origin IP</span>
        <span style="color:#e5c07b">● Sender Domain</span>
        <span style="color:#c678dd">● ASN</span>
        <span style="color:#d19a66">● Attachment Hash</span>
        <span style="color:#98c379">● Phishing URL</span>
    </div>
    """, unsafe_allow_html=True)

    tab_overview, tab_campaigns = st.tabs(["🌐 Master Entity Graph", "🎯 Campaign Clusters"])

    with tab_overview:
        svg_markup = render_graph_svg(data["full_graph"])
        st.markdown(svg_markup, unsafe_allow_html=True)

    with tab_campaigns:
        for camp in data["campaigns"]:
            is_cl = camp["is_cluster"]
            badge = "🚨 Coordinated Multi-Target Campaign" if is_cl else "Single-Incident Actor"
            with st.expander(f"**{camp['campaign_name']}** — {badge} ({camp['case_count']} Cases, Risk: {camp['avg_risk']}%)", expanded=is_cl):
                c_left, c_right = st.columns([1, 1])
                with c_left:
                    st.write("**Associated Cases:**")
                    for c in camp["cases"]:
                        st.markdown(f"- **`{c['case_id']}`**: `{c['file_name']}` (From: `{c['sender']}`, IP: `{c['origin_ip']}`, Risk: **{c['risk_score']}**)")
                with c_right:
                    sub_svg = render_graph_svg(camp["graph"], width=420, height=260)
                    st.markdown(sub_svg, unsafe_allow_html=True)