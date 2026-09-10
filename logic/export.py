# logic/export.py
import os
from fpdf import FPDF
from typing import Dict, Any
import datetime

def clean_text(text: Any) -> str:
    """Safely sanitizes text by replacing UI status badges and encoding for standard PDF fonts."""
    if text is None:
        return "N/A"
    if not isinstance(text, str):
        text = str(text)
    
    # Clean up standard UI status badge strings containing emojis
    text = text.replace("🔴 Malicious", "Malicious")
    text = text.replace("🟡 Suspicious", "Suspicious")
    text = text.replace("🟢 Safe (Trusted Institution)", "Safe (Trusted Institution)")
    text = text.replace("🟢 Safe", "Safe")
    
    # Encode to latin-1, replacing any remaining unsupported chars with '?', then decode back
    return text.encode('latin-1', 'replace').decode('latin-1').strip()

def generate_case_pdf(case_data: Dict[str, Any]) -> str:
    """Generates an exhaustive DFIR PDF report safely with defensive null-checks."""
    if not isinstance(case_data, dict):
        case_data = {}

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # --- DOCUMENT HEADER ---
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, "CYBERSECURITY INCIDENT FORENSIC REPORT", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "I", 9)
    pdf.cell(0, 5, f"Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC | Air-Gapped Analysis Engine", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)
    
    # --- SECTION 1: CASE OVERVIEW ---
    case_id = case_data.get('case_id', 'UNKNOWN')
    file_name = case_data.get('file_name', 'Unknown')
    file_hash = case_data.get('hash', 'Unknown')
    status = case_data.get('status', 'Unknown')
    risk_score = case_data.get('risk_score', 0)
    
    pdf.set_font("helvetica", "B", 11)
    pdf.set_fill_color(30, 58, 138)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 7, "  1. Case Overview & Identifiers", fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("helvetica", size=10)
    
    pdf.cell(0, 6, clean_text(f"Case Identifier: {case_id}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, clean_text(f"Artifact File Name: {file_name}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, clean_text(f"SHA256 Checksum: {file_hash}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, clean_text(f"Threat Status: {status} (Composite Risk Score: {risk_score}/100)"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # --- SECTION 2: EXECUTIVE THREAT BRIEFING ---
    pdf.set_font("helvetica", "B", 11)
    pdf.set_fill_color(30, 58, 138)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 7, "  2. Executive Threat Briefing", fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("helvetica", size=10)
    
    ai_insight = clean_text(case_data.get('ai_insight', 'No summary available.'))
    pdf.multi_cell(0, 5, ai_insight)
    pdf.ln(4)

    # --- SECTION 3: PROTOCOL AUTHENTICATION & ORIGIN ---
    auth = case_data.get("auth") or {}
    geo = case_data.get("geo") or {}
    
    pdf.set_font("helvetica", "B", 11)
    pdf.set_fill_color(30, 58, 138)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 7, "  3. Protocol Authentication & Origin Telemetry", fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("helvetica", size=10)
    
    pdf.cell(0, 6, clean_text(f"Sender Domain: {auth.get('domain', 'Unknown')}"), new_x="LMARGIN", new_y="NEXT")
    spf = auth.get('spf') or {}
    pdf.cell(0, 6, clean_text(f"SPF Status: {spf.get('status', 'N/A')} - {spf.get('details', '')}"), new_x="LMARGIN", new_y="NEXT")
    dkim = auth.get('dkim') or {}
    pdf.cell(0, 6, clean_text(f"DKIM Status: {dkim.get('status', 'N/A')}"), new_x="LMARGIN", new_y="NEXT")
    dmarc = auth.get('dmarc') or {}
    pdf.cell(0, 6, clean_text(f"DMARC Policy: {dmarc.get('policy', 'N/A')}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, clean_text(f"Origin Source IP: {geo.get('ip', 'Unknown')} ({geo.get('country', 'Unknown')}) | Org: {geo.get('org', 'N/A')}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # --- SECTION 4: THREAT INDICATORS & PAYLOADS ---
    pdf.set_font("helvetica", "B", 11)
    pdf.set_fill_color(30, 58, 138)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 7, "  4. Threat Indicators & Payloads", fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("helvetica", size=10)
    
    decomp = case_data.get("decomp") or {}
    attachments = decomp.get("attachments") or []
    if attachments:
        pdf.cell(0, 6, f"Attached Payloads Detected ({len(attachments)}):", new_x="LMARGIN", new_y="NEXT")
        for att in attachments:
            if isinstance(att, dict):
                pdf.cell(0, 5, clean_text(f" - {att.get('filename')} ({att.get('size_kb')} KB) | SHA256: {att.get('sha256')}"), new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(0, 6, "Attached Payloads: None detected.", new_x="LMARGIN", new_y="NEXT")
        
    heur = case_data.get("heur") or {}
    keywords = clean_text(', '.join(heur.get('keywords', []) or []))
    pdf.cell(0, 6, f"Trigger Keywords Found: {keywords}", new_x="LMARGIN", new_y="NEXT")
    
    urls = heur.get("urls") or []
    if urls:
        pdf.cell(0, 6, f"Extracted URLs ({len(urls)}):", new_x="LMARGIN", new_y="NEXT")
        for url in urls[:5]:
            pdf.cell(0, 5, clean_text(f" - {url}"), new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(0, 6, "Extracted URLs: None detected.", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # --- SECTION 5: RECOMMENDED ACTIONS ---
    pdf.set_font("helvetica", "B", 11)
    pdf.set_fill_color(30, 58, 138)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 7, "  5. Recommended Incident Response Actions", fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("helvetica", size=10)
    
    pdf.cell(0, 6, "[  ] 1. Isolate the affected mailbox and verify user activity logs.", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, "[  ] 2. Add malicious sender domain / originating IP to local blocklist.", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, "[  ] 3. Purge similar email artifacts across corporate mailboxes via message trace.", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, "[  ] 4. Force credential reset if user interacted with extracted links or attachments.", new_x="LMARGIN", new_y="NEXT")

    pdf_bytes = bytes(pdf.output())

    # --- AUTOMATIC UNIQUE LOCAL BACKUP SAVE ---
    try:
        os.makedirs("Case Reports", exist_ok=True)
        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"{case_id}_{timestamp_str}_Report.pdf"
        file_path = os.path.abspath(os.path.join("Case Reports", file_name))
        
        with open(file_path, "wb") as f:
            f.write(pdf_bytes)
        return file_path
    except Exception as e:
        print(f"[!] Warning: Could not save local backup report: {e}")
        return ""