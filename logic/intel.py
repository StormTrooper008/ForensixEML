# logic/intel.py
import re
from logic.database import get_db_connection
from logic.domain_intel import get_domain_intelligence

def check_ledger_intelligence(sender_header: str, origin_ip: str, extracted_urls: list) -> dict:
    """Cross-references email artifacts against internal personnel, blocklists, and live DNS/WHOIS."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    intelligence = {
        "is_spoofing": False,
        "spoofed_user": None,
        "blocklist_hits": [],
        "penalty": 0,
        "domain_whois": {} # <-- NEW: Storing the domain infrastructure data
    }
    
    # --- 1. Personnel Spoofing Detection ---
    name_part = ""
    email_part = sender_header
    match = re.match(r"(.*)<(.*)>", sender_header)
    if match:
        name_part = match.group(1).strip().strip('"').strip("'")
        email_part = match.group(2).strip()
        
    if name_part:
        cursor.execute("SELECT email, designation FROM personnel WHERE full_name COLLATE NOCASE = ?", (name_part,))
        emp = cursor.fetchone()
        if emp and emp["email"].lower() != email_part.lower():
            intelligence["is_spoofing"] = True
            intelligence["spoofed_user"] = f"{name_part} ({emp['designation']})"
            intelligence["penalty"] += 50

    sender_domain = email_part.split('@')[-1].lower() if '@' in email_part else ""

    # --- 2. Live Domain Recon (WHOIS/DNS) ---
    if sender_domain:
        domain_data = get_domain_intelligence(email_part)
        intelligence["domain_whois"] = domain_data
        
        # If the domain is under 30 days old, it's highly suspicious
        if domain_data.get("is_suspicious"):
            intelligence["blocklist_hits"].append(f"⚠️ Suspicious Domain: Registered recently (< 30 days old)")
            intelligence["penalty"] += 25

    # --- 3. Blocklist Checks ---
    cursor.execute("SELECT reason FROM blocklist WHERE indicator_type = 'IP' AND indicator_value = ?", (origin_ip,))
    hit = cursor.fetchone()
    if hit:
        intelligence["blocklist_hits"].append(f"Blocked IP: {origin_ip} ({hit['reason']})")
        intelligence["penalty"] += 50
        
    cursor.execute("SELECT reason FROM blocklist WHERE indicator_type = 'EMAIL' AND indicator_value = ?", (email_part,))
    hit = cursor.fetchone()
    if hit:
        intelligence["blocklist_hits"].append(f"Blocked Email: {email_part} ({hit['reason']})")
        intelligence["penalty"] += 50
        
    if sender_domain:
        cursor.execute("SELECT reason FROM blocklist WHERE indicator_type = 'DOMAIN' AND indicator_value = ?", (sender_domain,))
        hit = cursor.fetchone()
        if hit:
            intelligence["blocklist_hits"].append(f"Blocked Sender Domain: @{sender_domain} ({hit['reason']})")
            intelligence["penalty"] += 50
        
    for url in extracted_urls:
        domain_match = re.search(r"https?://([^/]+)", url)
        if domain_match:
            domain = domain_match.group(1).lower()
            cursor.execute("SELECT reason FROM blocklist WHERE indicator_type = 'DOMAIN' AND indicator_value = ?", (domain,))
            hit = cursor.fetchone()
            if hit:
                intelligence["blocklist_hits"].append(f"Blocked URL Domain: {domain} ({hit['reason']})")
                intelligence["penalty"] += 50
                
    conn.close()
    return intelligence