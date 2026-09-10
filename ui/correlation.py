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
    
    highlight_nodes = set()
    if selected_node and G.has_node(selected_node):
        highlight_nodes.add(selected_node)
        highlight_nodes.update(G.neighbors(selected_node))
        
        node_type = G.nodes[selected_node].get("node_type", "")
        
        # --- FEATURE 1: DEEP LINKING TO WORKBENCH ---
        if node_type == "CASE":
            col1, col2 = st.columns([2, 1])
            with col1:
                st.info(f"🎯 **Focus Mode:** Isolating connections for `{selected_node}`. Click background to reset.")
            with col2:
                # The teleport button
                if st.button(f"🔍 Investigate {selected_node} in Workbench", type="primary", use_container_width=True):
                    st.session_state.selected_case = selected_node
                    st.session_state.current_page = "🔬 Investigation Workbench"
                    st.rerun()
        else:
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
        
        if selected_node and node not in highlight_nodes:
            node_color = "rgba(30, 34, 42, 0.05)" 
            font_color = "rgba(0, 0, 0, 0)"      
            size = 5                              
        elif selected_node and node == selected_node:
            node_color = base_color
            font_color = "#ffffff"
            size = 45
        else:
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
            edge_color = "rgba(0, 0, 0, 0)" 
        else:
            edge_color = "#5c6370"
            
        edges.append(Edge(source=u, target=v, color=edge_color))
        
    config = Config(
        width=800,
        height=int(height.replace("px", "")),
        directed=False, 
        physics=True,  
        hierarchical=False,
        nodeSpacing=150,
        layout={"improvedLayout": False}
    )
    config.physics = {"enabled": True, "stabilization": {"iterations": 50}}

    clicked = agraph(nodes=nodes, edges=edges, config=config)
    
    if clicked != selected_node:
        st.session_state[f"selected_{graph_key}"] = clicked
        st.rerun()

def render_correlation_view():
    st.markdown("<h2>🕸️ Threat Graph & Campaign Correlation</h2>", unsafe_allow_html=True)
    st.caption("Click any node to isolate its connections. Click the background to reset.")

    # Initialize session state for custom campaign tags
    if "campaign_tags" not in st.session_state:
        st.session_state.campaign_tags = {}

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
            
            # Retrieve custom tag if it exists, otherwise fallback to the AI default
            camp_key = f"camp_tag_{idx}"
            display_name = st.session_state.campaign_tags.get(camp_key, camp['campaign_name'])
            
            # --- FEATURE 2: MINIMIZED BY DEFAULT ---
            with st.expander(f"**{display_name}** — {badge} ({camp['case_count']} Cases, Avg Risk: {camp['avg_risk']}%)", expanded=False):
                
                # --- FEATURE 3: CUSTOM TAGGING UI ---
                tag_col1, tag_col2 = st.columns([3, 1])
                with tag_col1:
                    new_tag = st.text_input("Assign Custom Tag/Name:", value=display_name, key=f"input_{camp_key}")
                with tag_col2:
                    st.write("") # Vertical padding alignment
                    st.write("")
                    if st.button("💾 Save Tag", key=f"btn_{camp_key}", use_container_width=True):
                        st.session_state.campaign_tags[camp_key] = new_tag
                        st.toast("Campaign tag successfully updated.")
                        st.rerun()
                        
                st.divider()

                c_left, c_right = st.columns([1, 1.5])
                with c_left:
                    st.write("**Associated Cases:**")
                    for c in camp["cases"]:
                        st.markdown(f"- **`{c['case_id']}`**: From: `{c['sender']}`, IP: `{c['origin_ip']}`, Risk: **{c['risk_score']}**")
                with c_right:
                    render_interactive_graph(camp["graph"], height="400px", graph_key=f"camp_graph_{idx}")