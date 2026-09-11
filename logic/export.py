# logic/export.py
import os
import datetime
from typing import Dict, Any

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
except ImportError:
    raise ImportError("ReportLab is required. Run: pip install reportlab")

def clean_text(text: Any) -> str:
    """Sanitizes text, escapes XML characters for ReportLab, and scrubs UI emojis."""
    if text is None:
        return "N/A"
    
    text = str(text)
    text = text.replace("🚨 Malicious", "Malicious")
    text = text.replace("🟡 Suspicious", "Suspicious")
    text = text.replace("🟢 Safe (Trusted Institution)", "Safe (Trusted Institution)")
    text = text.replace("🟢 Safe", "Safe")
    
    # ReportLab Paragraphs use XML, so we must escape brackets
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    return text.strip()

def force_wrap(text: str, width: int = 75) -> str:
    """Forces extremely long spaceless strings (URLs) to break using ReportLab's <br/> tag."""
    if not text:
        return ""
    return "<br/>".join([text[i:i+width] for i in range(0, len(text), width)])

def generate_case_pdf(case_data: Dict[str, Any]) -> str:
    """Generates an exhaustive, crash-proof DFIR PDF report using ReportLab."""
    if not isinstance(case_data, dict):
        case_data = {}

    case_id = case_data.get('case_id', 'UNKNOWN')
    
    # --- OUTPUT PATH SETUP ---
    os.makedirs("Case Reports", exist_ok=True)
    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f"{case_id}_{timestamp_str}_Report.pdf"
    file_path = os.path.abspath(os.path.join("Case Reports", file_name))

    # --- DOCUMENT INITIALIZATION ---
    doc = SimpleDocTemplate(file_path, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], alignment=1, spaceAfter=15)
    subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'], alignment=1, fontName="Helvetica-Oblique", spaceAfter=20)
    
    header_style = ParagraphStyle(
        'SectionHeader', 
        parent=styles['Heading2'],
        backColor=colors.HexColor("#1e3a8a"),
        textColor=colors.white,
        spaceBefore=15,
        spaceAfter=10,
        borderPadding=5
    )
    
    normal_style = styles['Normal']
    normal_style.spaceAfter = 6
    normal_style.fontSize = 10
    normal_style.leading = 14  # Line spacing

    bullet_style = ParagraphStyle('Bullet', parent=normal_style, leftIndent=15)

    elements = []

    # --- HEADER ---
    elements.append(Paragraph("<b>CYBERSECURITY INCIDENT FORENSIC REPORT</b>", title_style))
    elements.append(Paragraph(f"Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC | Air-Gapped Analysis Engine", subtitle_style))

    # --- SECTION 1: CASE OVERVIEW ---
    elements.append(Paragraph("1. Case Overview & Identifiers", header_style))
    elements.append(Paragraph(f"<b>Case Identifier:</b> {clean_text(case_id)}", normal_style))
    elements.append(Paragraph(f"<b>Artifact File Name:</b> {force_wrap(clean_text(case_data.get('file_name')))}", normal_style))
    elements.append(Paragraph(f"<b>SHA256 Checksum:</b> {clean_text(case_data.get('hash'))}", normal_style))
    elements.append(Paragraph(f"<b>Threat Status:</b> {clean_text(case_data.get('status'))} (Composite Risk Score: {case_data.get('risk_score', 0)}/100)", normal_style))

    # --- SECTION 2: EXECUTIVE THREAT BRIEFING ---
    elements.append(Paragraph("2. Executive Threat Briefing", header_style))
    elements.append(Paragraph(clean_text(case_data.get('ai_insight', 'No summary available.')), normal_style))

    # --- SECTION 3: PROTOCOL AUTHENTICATION & ORIGIN ---
    elements.append(Paragraph("3. Protocol Authentication & Origin Telemetry", header_style))
    
    auth = case_data.get("auth") or {}
    geo = case_data.get("geo") or {}
    intel = case_data.get("intel") or {}
    whois = intel.get("domain_whois") or {}
    
    elements.append(Paragraph(f"<b>Sender Domain:</b> {clean_text(auth.get('domain', 'Unknown'))}", normal_style))
    
    if whois and whois.get("status") != "OFFLINE" and not whois.get("error"):
        registrar = whois.get("registrar_full", whois.get("registrar", "Unknown"))
        age = whois.get("age_display", f"{whois.get('age_days', 'Unknown')} days")
        creation = whois.get("creation_date", "Unknown")
        elements.append(Paragraph(f"<b>Domain Registrar:</b> {clean_text(registrar)} | <b>Created:</b> {clean_text(creation)} | <b>Age:</b> {clean_text(age)}", normal_style))
        
    spf = auth.get('spf') or {}
    dkim = auth.get('dkim') or {}
    dmarc = auth.get('dmarc') or {}
    
    elements.append(Paragraph(f"<b>SPF Status:</b> {clean_text(spf.get('status', 'N/A'))} - {clean_text(spf.get('details', ''))}", normal_style))
    elements.append(Paragraph(f"<b>DKIM Status:</b> {clean_text(dkim.get('status', 'N/A'))}", normal_style))
    elements.append(Paragraph(f"<b>DMARC Policy:</b> {clean_text(dmarc.get('policy', 'N/A'))}", normal_style))
    elements.append(Paragraph(f"<b>Origin Source IP:</b> {clean_text(geo.get('ip', 'Unknown'))} ({clean_text(geo.get('country', 'Unknown'))}) | <b>Org:</b> {clean_text(geo.get('org', 'N/A'))}", normal_style))

    # --- SECTION 4: THREAT INDICATORS & PAYLOADS ---
    elements.append(Paragraph("4. Threat Indicators & Payloads", header_style))
    
    decomp = case_data.get("decomp") or {}
    attachments = decomp.get("attachments") or []
    if attachments:
        elements.append(Paragraph(f"<b>Attached Payloads Detected ({len(attachments)}):</b>", normal_style))
        for att in attachments:
            if isinstance(att, dict):
                att_str = clean_text(f"{att.get('filename')} ({att.get('size_kb')} KB) | SHA256: {att.get('sha256')}")
                elements.append(Paragraph(f"• {force_wrap(att_str)}", bullet_style))
    else:
        elements.append(Paragraph("<b>Attached Payloads:</b> None detected.", normal_style))
        
    heur = case_data.get("heur") or {}
    keywords_raw = clean_text(', '.join(heur.get('keywords', []) or []))
    elements.append(Paragraph(f"<b>Trigger Keywords Found:</b> {force_wrap(keywords_raw)}", normal_style))
    
    urls = heur.get("urls") or []
    if urls:
        elements.append(Paragraph(f"<b>Extracted URLs ({len(urls)}):</b>", normal_style))
        for url in urls[:5]:
            elements.append(Paragraph(f"• {force_wrap(clean_text(url))}", bullet_style))
    else:
        elements.append(Paragraph("<b>Extracted URLs:</b> None detected.", normal_style))

    # --- SECTION 5: RECOMMENDED ACTIONS ---
    elements.append(Paragraph("5. Recommended Incident Response Actions", header_style))
    
    actions = [
        "[  ] 1. Isolate the affected mailbox and verify user activity logs.",
        "[  ] 2. Add malicious sender domain / originating IP to local blocklist.",
        "[  ] 3. Purge similar email artifacts across corporate mailboxes via message trace.",
        "[  ] 4. Force credential reset if user interacted with extracted links or attachments."
    ]
    
    for action in actions:
        elements.append(Paragraph(action, normal_style))

    # --- BUILD DOCUMENT ---
    try:
        doc.build(elements)
        return file_path
    except Exception as e:
        print(f"[!] Warning: Could not build PDF report: {e}")
        return ""