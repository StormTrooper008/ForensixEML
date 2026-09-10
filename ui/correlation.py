# ui/correlation.py
import streamlit as st
import networkx as nx
from streamlit_agraph import agraph, Node, Edge, Config
from logic.correlation import build_threat_graph

def render_interactive_graph(G: nx.Graph, height="500px", graph_key="main_graph") -> None:
    """Renders the graph and supports click-to-highlight functionality."""
    if G.number_of_nodes() == 0:
        st.info("Empty Graph")
        return

    # Check if a node was previously clicked to apply highlight logic
    selected_node = st.session_state.get(f"selected_{graph_key}", None)
    
    # Determine the neighborhood of the clicked node
    # Determine the neighborhood of the clicked node
    highlight_nodes = set()
    if selected_node and G.has_node(selected_node):
        highlight_nodes.add(selected_node)
        highlight_nodes.update(G.neighbors(selected_node))
        
        # Display a banner confirming what is selected
        st.info(f"🎯 **Focus Mode:** Isolating connections for `{selected_node}`. Click the background to reset.")

    nodes = []
    edges = []
    
    color_map = {
        "CASE": "#e06c75", "IP": "#61afef", "DOMAIN": "#e5c07b", 
        "ASN": "#c678dd", "ATTACHMENT": "#d19a66", "URL": "#98c379"
    }

    for node, data in G.nodes(data=True):
        n_type = data.get("node_type", "CASE")
        base_color = color_map.get(n_type, "#abb2bf")
        
        # --- THE NEW GHOSTING LOGIC ---
        if selected_node and node not in highlight_nodes:
            # Unrelated Nodes: 95% transparent, invisible text, tiny size
            node_color = "rgba(30, 34, 42, 0.05)" 
            font_color = "rgba(0, 0, 0, 0)"      
            size = 5                              
        elif selected_node and node == selected_node:
            # The Clicked Node: Massive size, bright text
            node_color = base_color
            font_color = "#ffffff"
            size = 45
        else:
            # Neighbors (or default unselected state)
            node_color = base_color
            font_color = "#d8dee9"
            size = 25 if n_type == "CASE" else 15
            
        title = f"{n_type}:\n{data.get('label', node)}"
        if n_type == "CASE":
            title += f"\nRisk: {data.get('risk', 'N/A')}"
            
        nodes.append(Node(
            id=node,
            label=str(data.get("label", node))[:15],
            size=size,
            color=node_color,
            title=title,
            font={"color": font_color}
        ))
        
    for u, v in G.edges():
        if selected_node and (u not in highlight_nodes or v not in highlight_nodes):
            edge_color = "rgba(0, 0, 0, 0)" # Unrelated edges become 100% invisible
        else:
            edge_color = "#5c6370"
            
        edges.append(Edge(source=u, target=v, color=edge_color))
        
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

    # Capture the click event
    clicked = agraph(nodes=nodes, edges=edges, config=config)
    
    # Update state and rerun if a new node was clicked
    if clicked != selected_node:
        st.session_state[f"selected_{graph_key}"] = clicked
        st.rerun()

def render_correlation_view():
    st.markdown("<h2>🕸️ Threat Graph & Campaign Correlation</h2>", unsafe_allow_html=True)
    st.caption("Click any node to isolate its connections. Click the background to reset.")

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
        if st.button("🔄 Reset Graph Highlight"):
            st.session_state["selected_main_graph"] = None
            st.rerun()
        render_interactive_graph(data["full_graph"], height="700px", graph_key="main_graph")

    with tab_campaigns:
        for idx, camp in enumerate(data["campaigns"]):
            is_cl = camp["is_cluster"]
            badge = "🚨 Coordinated Campaign" if is_cl else "Single-Incident"
            with st.expander(f"**{camp['campaign_name']}** — {badge} ({camp['case_count']} Cases, Avg Risk: {camp['avg_risk']}%)", expanded=is_cl):
                c_left, c_right = st.columns([1, 1.5])
                with c_left:
                    st.write("**Associated Cases:**")
                    for c in camp["cases"]:
                        st.markdown(f"- **`{c['case_id']}`**: From: `{c['sender']}`, IP: `{c['origin_ip']}`, Risk: **{c['risk_score']}**")
                with c_right:
                    render_interactive_graph(camp["graph"], height="400px", graph_key=f"camp_graph_{idx}")