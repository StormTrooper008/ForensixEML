# logic/correlation.py
import json
import sqlite3
import networkx as nx
from typing import Dict, List, Any
from logic.database import get_db_connection

def extract_indicators_from_telemetry(case_id: str, tel: Dict[str, Any], sender: str, origin_ip: str) -> List[Dict[str, str]]:
    """Extracts forensic correlation nodes from a single case telemetry packet."""
    indicators = []
    
    # 1. Originating IP
    if origin_ip and origin_ip not in ["127.0.0.1", "0.0.0.0", ""]:
        indicators.append({"type": "IP", "value": origin_ip, "label": f"IP: {origin_ip}"})
        
    # 2. Sender Domain
    if "@" in sender:
        domain = sender.split("@")[-1].replace(">", "").strip().lower()
        if domain:
            indicators.append({"type": "DOMAIN", "value": domain, "label": f"Domain: {domain}"})
            
    # 3. ASN / Hosting Infrastructure
    asn = tel.get("geo", {}).get("asn", "")
    if asn and asn not in ["Unknown", "Private", ""]:
        indicators.append({"type": "ASN", "value": asn, "label": f"ASN: {asn}"})
        
    # 4. Attachment Payloads (SHA256)
    attachments = tel.get("decomp", {}).get("attachments", [])
    for att in attachments:
        sha = att.get("sha256")
        if sha:
            indicators.append({"type": "ATTACHMENT", "value": sha[:12], "label": f"SHA: {sha[:8]}.. ({att.get('filename', 'file')})"})
            
    # 5. Phishing URLs & Domains
    urls = tel.get("heur", {}).get("urls", [])
    for url in urls[:5]:
        indicators.append({"type": "URL", "value": url, "label": f"URL: {url[:30]}..."})
        
    return indicators

def build_threat_graph() -> Dict[str, Any]:
    """
    Builds a NetworkX graph across all ingested cases.
    Includes aggressive error handling for malformed database rows.
    """
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row if hasattr(sqlite3, "Row") else conn.row_factory
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT case_id, file_name, sender, origin_ip, risk_score, status, telemetry, timestamp FROM cases")
        rows = cursor.fetchall()
    except Exception as e:
        print(f"Database Query Error: {e}")
        return {"total_cases": 0, "total_nodes": 0, "total_edges": 0, "campaigns": [], "full_graph": nx.Graph()}
    finally:
        conn.close()

    G = nx.Graph()
    cases_meta = {}

    for row in rows:
        try:
            c_id = row["case_id"]
            risk = row["risk_score"]
            status = row["status"]
            
            tel_raw = row["telemetry"]
            tel = {}
            if tel_raw:
                try:
                    tel = json.loads(tel_raw)
                except json.JSONDecodeError:
                    tel = {}
            
            cases_meta[c_id] = {
                "file_name": row["file_name"],
                "sender": row["sender"],
                "origin_ip": row["origin_ip"],
                "risk_score": risk,
                "status": status,
                "timestamp": row["timestamp"]
            }
            
            G.add_node(c_id, node_type="CASE", label=c_id, risk=risk, status=status)
            
            indicators = extract_indicators_from_telemetry(c_id, tel, row["sender"], row["origin_ip"])
            for ind in indicators:
                node_key = f"{ind['type']}::{ind['value']}"
                if not G.has_node(node_key):
                    G.add_node(node_key, node_type=ind["type"], label=ind["label"], risk=risk)
                G.add_edge(c_id, node_key)
                
        except Exception as e:
            print(f"Skipping corrupted case row {row.get('case_id', 'UNKNOWN')}: {e}")
            continue

    subgraphs = [G.subgraph(c).copy() for c in nx.connected_components(G)]
    
    campaigns = []
    for idx, sg in enumerate(subgraphs):
        case_nodes = [n for n, d in sg.nodes(data=True) if d.get("node_type") == "CASE"]
        indicator_nodes = [n for n, d in sg.nodes(data=True) if d.get("node_type") != "CASE"]
        
        if not case_nodes:
            continue
            
        avg_risk = sum(cases_meta[c]["risk_score"] for c in case_nodes) / len(case_nodes)
        
        shared_ips = [d["label"] for n, d in sg.nodes(data=True) if d.get("node_type") == "IP"]
        shared_attachments = [d["label"] for n, d in sg.nodes(data=True) if d.get("node_type") == "ATTACHMENT"]
        
        camp_id = f"CAMP-{idx+1:03d}"
        if shared_ips:
            camp_name = f"{camp_id} ({shared_ips[0]})"
        elif shared_attachments:
            camp_name = f"{camp_id} [Shared Payload]"
        else:
            camp_name = f"{camp_id} [Domain Cluster]"

        cases_list = []
        for c in case_nodes:
            c_dict = cases_meta[c].copy()
            c_dict["case_id"] = c
            cases_list.append(c_dict)

        campaigns.append({
            "campaign_id": camp_id,
            "campaign_name": camp_name,
            "case_count": len(case_nodes),
            "cases": cases_list,
            "indicator_count": len(indicator_nodes),
            "avg_risk": round(avg_risk, 1),
            "is_cluster": len(case_nodes) > 1,
            "graph": sg
        })

    campaigns.sort(key=lambda x: (x["is_cluster"], x["avg_risk"]), reverse=True)
    return {"total_cases": len(rows), "total_nodes": G.number_of_nodes(), "total_edges": G.number_of_edges(), "campaigns": campaigns, "full_graph": G}