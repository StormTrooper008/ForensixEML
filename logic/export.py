from fpdf import FPDF
from typing import Dict, Any

def clean_text(text: str) -> str:
    """Removes emojis and unsupported Unicode characters for basic PDF fonts."""
    if not isinstance(text, str):
        text = str(text)
    # Encodes to ascii/latin-1, replacing unsupported chars with '?', then decodes back
    return text.encode('latin-1', 'replace').decode('latin-1')

def generate_case_pdf(case_data: Dict[str, Any]) -> bytes:
    """Generates a structured PDF report from forensic case data."""
    pdf = FPDF()
    pdf.add_page()
    
    # Header
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, "Email Forensic Case Report", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    # Case Summary
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 10, clean_text(f"Case Identifier: {case_data.get('case_id', 'Unknown')}"), new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("helvetica", size=11)
    pdf.cell(0, 8, clean_text(f"File Name: {case_data.get('file_name', '')}"), new_x="LMARGIN", new_y="NEXT")
    
    # Clean the status string so the emojis (🔴/🟢) don't crash the PDF engine
    clean_status = clean_text(case_data.get('status', ''))
    pdf.cell(0, 8, f"Threat Status: {clean_status} (Risk Score: {case_data.get('risk_score', 0)})", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    # Authentication Intelligence
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 10, "Protocol Authentication & Origin", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("helvetica", size=11)
    auth = case_data.get("auth", {})
    pdf.cell(0, 8, clean_text(f"SPF Record: {auth.get('spf', {}).get('status', 'N/A')}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, clean_text(f"DMARC Policy: {auth.get('dmarc', {}).get('policy', 'N/A')}"), new_x="LMARGIN", new_y="NEXT")

    dkim_status = auth.get('dkim', {}).get('status', 'N/A')
    pdf.cell(0, 8, clean_text(f"DKIM Signature: {dkim_status}"), new_x="LMARGIN", new_y="NEXT")
    
    geo = case_data.get("geo", {})
    pdf.cell(0, 8, clean_text(f"Origin Source IP: {geo.get('ip', 'Unknown')} ({geo.get('country', 'Unknown')})"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Heuristics
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 10, "Phishing Heuristics", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", size=11)
    
    heur = case_data.get("heur", {})
    keywords = clean_text(', '.join(heur.get('keywords', [])) or 'None')
    pdf.cell(0, 8, f"Trigger Keywords Found: {keywords}", new_x="LMARGIN", new_y="NEXT")
    
    # Convert bytearray to standard bytes for Streamlit
    return bytes(pdf.output())