# ui/correlation.py
import streamlit as st
import networkx as nx
from streamlit_agraph import agraph, Node, Edge, Config
from logic.correlation import build_threat_graph

def render_interactive_graph(G: nx.Graph, height="500px") -> None:
    """Renders a fully interactive, physics-based network graph natively in Streamlit."""
    if G.number_of_nodes() == 0:
        st.info("Empty Graph")
        return

    nodes = []
    edges = []
    
    color_map = {
        "CASE": "#e06c75", "IP": "#61afef", "DOMAIN": "#e5c07b", 
        "ASN": "#c678dd", "ATTACHMENT": "#d19a66", "URL": "#98c379"
    }

    # 1. Build Native Nodes
    for node, data in G.nodes(data=True):
        n_type = data.get("node_type", "CASE")
        color = color_map.get(n_type, "#abb2bf")
        size = 25 if n_type == "CASE" else 15
        
        title = f"{n_type}:\n{data.get('label', node)}"
        if n_type == "CASE":
            title += f"\nRisk: {data.get('risk', 'N/A')}"
            
        nodes.append(Node(
            id=node,
            label=str(data.get("label", node))[:15],
            size=size,
            color=color,
            title=title
        ))
        
    # 2. Build Native Edges
    for u, v in G.edges():
        edges.append(Edge(source=u, target=v, color="#3b4252"))
        
    # 3. Configure Native Physics & Layout
    config = Config(
        width=800,
        height=int(height.replace("px", "")),
        directed=False, 
        physics=True,  # Keeps Python's type-checker happy
        hierarchical=False,
        nodeSpacing=150,
        layout={"improvedLayout": False}
    )
    # Bypasses the type-checker to send advanced settings directly to the JS engine
    config.physics = {"enabled": True, "stabilization": {"iterations": 50}}

    # 4. Render instantly (no HTML tempfiles)
    agraph(nodes=nodes, edges=edges, config=config)

def render_correlation_view():
    st.markdown("<h2>🕸️ Threat Graph & Campaign Correlation</h2>", unsafe_allow_html=True)
    st.caption("Native interactive graph analysis. Drag nodes, zoom in/out, and hover for detailed entity telemetry.")

    data = build_threat_graph()
    
    if data["total_cases"] == 0:
        st.info("No ingested cases found. Please process `.eml` files first.")
        return

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Tracked Cases", data["total_cases"])
    m2.metric("Linked Entities", data["total_nodes"])
    m3.metric("Correlation Edges", data["total_edges"])
    m4.metric("Coordinated Campaigns", len([c for c in data["campaigns"] if c["is_cluster"]]))

    st.write("")
    st.markdown("""
    <div style="display:flex; gap:15px; flex-wrap:wrap; background-color:#1e222a; padding:10px; border-radius:6px; font-size:13px; margin-bottom:15px;">
        <span style="color:#e06c75">● Case</span> <span style="color:#61afef">● Origin IP</span>
        <span style="color:#e5c07b">● Sender Domain</span> <span style="color:#c678dd">● ASN</span>
        <span style="color:#d19a66">● Attachment Hash</span> <span style="color:#98c379">● Phishing URL</span>
    </div>
    """, unsafe_allow_html=True)

    tab_overview, tab_campaigns = st.tabs(["🌐 Master Entity Graph", "🎯 Campaign Clusters"])

    with tab_overview:
        render_interactive_graph(data["full_graph"], height="700px")

    with tab_campaigns:
        for camp in data["campaigns"]:
            is_cl = camp["is_cluster"]
            badge = "🚨 Coordinated Campaign" if is_cl else "Single-Incident"
            with st.expander(f"**{camp['campaign_name']}** — {badge} ({camp['case_count']} Cases, Avg Risk: {camp['avg_risk']}%)", expanded=is_cl):
                c_left, c_right = st.columns([1, 1.5]) # Gave the graph column a bit more width
                with c_left:
                    st.write("**Associated Cases:**")
                    for c in camp["cases"]:
                        st.markdown(f"- **`{c['case_id']}`**: From: `{c['sender']}`, IP: `{c['origin_ip']}`, Risk: **{c['risk_score']}**")
                with c_right:
                    render_interactive_graph(camp["graph"], height="400px")