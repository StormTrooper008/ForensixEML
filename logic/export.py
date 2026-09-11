# logic/export.py
import os
import datetime
from typing import Dict, Any

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
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
    
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    return text.strip()

def force_wrap(text: str, width: int = 85) -> str:
    """Forces extremely long spaceless strings (URLs) to break using ReportLab's <br/> tag."""
    if not text:
        return ""
    return "<br/>".join([text[i:i+width] for i in range(0, len(text), width)])

def generate_case_pdf(case_data: Dict[str, Any]) -> str:
    """Generates a highly polished, tabular DFIR PDF report."""
    if not isinstance(case_data, dict):
        case_data = {}

    case_id = case_data.get('case_id', 'UNKNOWN')
    
    # --- OUTPUT PATH SETUP ---
    os.makedirs("Case Reports", exist_ok=True)
    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f"{case_id}_{timestamp_str}_Report.pdf"
    file_path = os.path.abspath(os.path.join("Case Reports", file_name))

    # --- DOCUMENT INITIALIZATION ---
    # A4 width is ~595 points. With 30pt margins, we have 535 points of usable width.
    doc = SimpleDocTemplate(file_path, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    styles = getSampleStyleSheet()
    
    # Custom Typography
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], alignment=1, fontSize=18, spaceAfter=5, textColor=colors.HexColor("#0f172a"))
    subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'], alignment=1, fontSize=10, textColor=colors.HexColor("#64748b"), spaceAfter=20)
    
    header_style = ParagraphStyle(
        'SectionHeader', 
        parent=styles['Heading2'],
        backColor=colors.HexColor("#1e3a8a"),
        textColor=colors.white,
        fontSize=12,
        spaceBefore=15,
        spaceAfter=10,
        borderPadding=6
    )
    
    normal_style = styles['Normal']
    normal_style.fontSize = 10
    normal_style.leading = 14
    
    # Custom style for raw URLs and hashes to make them look like code
    code_style = ParagraphStyle('Code', parent=normal_style, fontName="Courier", fontSize=8.5, leading=10, textColor=colors.HexColor("#b91c1c"))
    bullet_style = ParagraphStyle('Bullet', parent=normal_style, leftIndent=15)

    # Standard Table Design
    standard_table_style = TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f8fafc")), # Light gray key column
        ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor("#0f172a")),  # Dark text
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),             # Bold keys
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1"))  # Clean grid lines
    ])

    elements = []

    # --- HEADER ---
    elements.append(Paragraph("<b>CYBERSECURITY INCIDENT DOSSIER</b>", title_style))
    elements.append(Paragraph(f"Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC | Air-Gapped Analysis Engine", subtitle_style))

    # --- SECTION 1: CASE OVERVIEW ---
    elements.append(Paragraph("1. Case Overview & Identifiers", header_style))
    
    overview_data = [
        ["Case Identifier", clean_text(case_id)],
        ["Artifact File Name", Paragraph(clean_text(case_data.get('file_name')), normal_style)],
        ["SHA256 Checksum", Paragraph(clean_text(case_data.get('hash')), code_style)],
        ["Threat Status", f"{clean_text(case_data.get('status'))} (Risk Score: {case_data.get('risk_score', 0)}/100)"]
    ]
    t1 = Table(overview_data, colWidths=[135, 400])
    t1.setStyle(standard_table_style)
    elements.append(t1)

    # --- SECTION 2: EXECUTIVE THREAT BRIEFING ---
    elements.append(Paragraph("2. Executive Threat Briefing", header_style))
    ai_insight = clean_text(case_data.get('ai_insight', 'No summary available.'))
    
    # Put the AI insight inside a shaded alert box
    insight_data = [[Paragraph(ai_insight, normal_style)]]
    t2 = Table(insight_data, colWidths=[535])
    t2.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f0fdf4")), # Very light green/gray
        ('BORDER', (0,0), (-1,-1), 1, colors.HexColor("#bbf7d0")),
        ('PADDING', (0,0), (-1,-1), 10)
    ]))
    elements.append(t2)

    # --- SECTION 3: PROTOCOL AUTHENTICATION & ORIGIN ---
    elements.append(Paragraph("3. Protocol Authentication & Origin Telemetry", header_style))
    
    auth = case_data.get("auth") or {}
    geo = case_data.get("geo") or {}
    intel = case_data.get("intel") or {}
    whois = intel.get("domain_whois") or {}
    
    spf = auth.get('spf') or {}
    dkim = auth.get('dkim') or {}
    dmarc = auth.get('dmarc') or {}
    
    auth_data = [
        ["Sender Domain", clean_text(auth.get('domain', 'Unknown'))],
        ["SPF Status", f"{clean_text(spf.get('status', 'N/A'))} - {clean_text(spf.get('details', ''))}"],
        ["DKIM Status", clean_text(dkim.get('status', 'N/A'))],
        ["DMARC Policy", clean_text(dmarc.get('policy', 'N/A'))],
        ["Origin Source IP", f"{clean_text(geo.get('ip', 'Unknown'))} ({clean_text(geo.get('country', 'Unknown'))})"],
        ["Infrastructure Org", clean_text(geo.get('org', 'N/A'))]
    ]
    
    if whois and whois.get("status") != "OFFLINE" and not whois.get("error"):
        registrar = whois.get("registrar_full", whois.get("registrar", "Unknown"))
        age = whois.get("age_display", f"{whois.get('age_days', 'Unknown')} days")
        auth_data.append(["Domain Registrar", clean_text(registrar)])
        auth_data.append(["Domain Age", clean_text(age)])

    t3 = Table(auth_data, colWidths=[135, 400])
    t3.setStyle(standard_table_style)
    elements.append(t3)

    # --- SECTION 4: THREAT INDICATORS & PAYLOADS ---
    elements.append(Paragraph("4. Threat Indicators & Payloads", header_style))
    
    decomp = case_data.get("decomp") or {}
    
    # Keywords
    heur = case_data.get("heur") or {}
    keywords_raw = clean_text(', '.join(heur.get('keywords', []) or []))
    if keywords_raw:
        elements.append(Paragraph(f"<b>Trigger Keywords:</b> {keywords_raw}", normal_style))
        elements.append(Spacer(1, 8))

    # Attachments
    attachments = decomp.get("attachments") or []
    if attachments:
        elements.append(Paragraph(f"<b>Attached Payloads Detected ({len(attachments)}):</b>", normal_style))
        for att in attachments:
            if isinstance(att, dict):
                att_str = clean_text(f"{att.get('filename')} ({att.get('size_kb')} KB) | SHA256: {att.get('sha256')}")
                elements.append(Paragraph(f"• {force_wrap(att_str)}", code_style))
    else:
        elements.append(Paragraph("<b>Attached Payloads:</b> None detected.", normal_style))
    
    elements.append(Spacer(1, 8))
    
    # URLs (Using the Code style for monospace rendering)
    urls = heur.get("urls") or []
    if urls:
        elements.append(Paragraph(f"<b>Extracted URLs ({len(urls)}):</b>", normal_style))
        for url in urls[:5]:
            elements.append(Paragraph(f"• {force_wrap(clean_text(url))}", code_style))
    else:
        elements.append(Paragraph("<b>Extracted URLs:</b> None detected.", normal_style))

    # --- SECTION 5: RECOMMENDED ACTIONS ---
    elements.append(Paragraph("5. Recommended Incident Response Actions", header_style))
    
    actions = [
        "☐ Isolate the affected mailbox and verify user activity logs.",
        "☐ Add malicious sender domain / originating IP to local blocklist.",
        "☐ Purge similar email artifacts across corporate mailboxes via message trace.",
        "☐ Force credential reset if user interacted with extracted links or attachments."
    ]
    
    for action in actions:
        elements.append(Paragraph(action, bullet_style))
        elements.append(Spacer(1, 4))

    # --- BUILD DOCUMENT ---
    try:
        doc.build(elements)
        return file_path
    except Exception as e:
        print(f"[!] Warning: Could not build PDF report: {e}")
        return ""