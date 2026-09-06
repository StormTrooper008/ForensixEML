import re
from logic.database import get_db_connection

def check_ledger_intelligence(sender_header: str, origin_ip: str, extracted_urls: list) -> dict:
    """Cross-references email artifacts against internal employees and blocklists."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    intelligence = {
        "is_spoofing": False,
        "spoofed_user": None,
        "blocklist_hits": [],
        "penalty": 0
    }
    
    # --- 1. Employee Spoofing Detection ---
    # Attempt to split "Name <email@domain.com>"
    name_part = ""
    email_part = sender_header
    match = re.match(r"(.*)<(.*)>", sender_header)
    if match:
        name_part = match.group(1).strip().strip('"').strip("'")
        email_part = match.group(2).strip()
        
    if name_part:
        # Check if the display name matches a protected employee (case-insensitive)
        cursor.execute("SELECT email, designation FROM employees WHERE full_name COLLATE NOCASE = ?", (name_part,))
        emp = cursor.fetchone()
        
        # If the name matches, but the sending email doesn't match their real email: SPOOF DETECTED
        if emp and emp["email"].lower() != email_part.lower():
            intelligence["is_spoofing"] = True
            intelligence["spoofed_user"] = f"{name_part} ({emp['designation']})"
            intelligence["penalty"] += 50
            
    # --- 2. Blocklist Checks ---
    # Check IP
    cursor.execute("SELECT reason FROM blocklist WHERE indicator_type = 'IP' AND indicator_value = ?", (origin_ip,))
    hit = cursor.fetchone()
    if hit:
        intelligence["blocklist_hits"].append(f"Blocked IP: {origin_ip} ({hit['reason']})")
        intelligence["penalty"] += 50
        
    # Check Sender Email
    cursor.execute("SELECT reason FROM blocklist WHERE indicator_type = 'EMAIL' AND indicator_value = ?", (email_part,))
    hit = cursor.fetchone()
    if hit:
        intelligence["blocklist_hits"].append(f"Blocked Email: {email_part} ({hit['reason']})")
        intelligence["penalty"] += 50
        
    # Check URLs against Domain Blocklist
    for url in extracted_urls:
        domain_match = re.search(r"https?://([^/]+)", url)
        if domain_match:
            domain = domain_match.group(1)
            cursor.execute("SELECT reason FROM blocklist WHERE indicator_type = 'DOMAIN' AND indicator_value = ?", (domain,))
            hit = cursor.fetchone()
            if hit:
                intelligence["blocklist_hits"].append(f"Blocked Domain: {domain} ({hit['reason']})")
                intelligence["penalty"] += 50
                
    conn.close()
    return intelligence