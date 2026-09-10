import sqlite3
import json
import whois
import dns.resolver
import datetime
import socket
from logic.database import get_db_connection

def check_internet_connection(host="8.8.8.8", port=53, timeout=1.5):
    """Fast socket check to see if the system is currently online."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except OSError:
        return False

def init_domain_cache():
    """Ensures the local domain caching table exists for offline support."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS domain_cache (
            domain TEXT PRIMARY KEY,
            intel_data TEXT,
            last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def extract_domain_from_email(email_address: str) -> str:
    """Safely extracts just the domain from an email string."""
    if not email_address or "@" not in email_address:
        return ""
    return email_address.split("@")[-1].strip().lower()

def perform_live_recon(domain: str) -> dict:
    """Actively queries public DNS and WHOIS servers with safe fallbacks for institutional domains."""
    intel = {
        "domain": domain,
        "registrar": "Unknown",
        "creation_date": "Unknown",
        "age_days": 999, # Default to a safe high number so failed lookups don't trigger "0-day" alarms
        "mx_records": [],
        "a_records": [],
        "txt_records": [],
        "is_suspicious": False,
        "status": "ONLINE_SUCCESS"
    }
    
    # Institutional Whitelist Check (Government / Official TLDs)
    trusted_tlds = [".gov.in", ".nic.in", ".mil", ".gov", ".edu"]
    is_trusted_institution = any(domain.endswith(tld) for tld in trusted_tlds)

    # 1. WHOIS Lookup
    try:
        w = whois.whois(domain)
        registrar = w.get("registrar")
        if registrar:
            intel["registrar"] = str(registrar)
            
        creation = w.get("creation_date")
        if isinstance(creation, list):
            creation = creation[0]
            
        if isinstance(creation, datetime.datetime):
            intel["creation_date"] = creation.strftime("%Y-%m-%d")
            intel["age_days"] = (datetime.datetime.now() - creation).days
            
            # Only flag as suspicious if it's truly new AND not a trusted institution
            if intel["age_days"] < 30 and not is_trusted_institution:
                intel["is_suspicious"] = True
    except Exception as e:
        print(f"[!] WHOIS lookup failed or timed out for {domain}: {e}")
        # If WHOIS fails on a government domain, assume it's safe rather than malicious
        if is_trusted_institution:
            intel["age_days"] = 3650 # Assume 10+ years old

    # 2. DNS Lookups
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    
    try:
        for rdata in resolver.resolve(domain, 'A'):
            intel["a_records"].append(rdata.to_text())
    except Exception: pass

    try:
        for rdata in resolver.resolve(domain, 'MX'):
            intel["mx_records"].append(rdata.exchange.to_text())
    except Exception: pass
    
    try:
        for rdata in resolver.resolve(domain, 'TXT'):
            intel["txt_records"].append(rdata.to_text())
    except Exception: pass

    return intel

def get_domain_intelligence(email_address: str) -> dict:
    """The main interface: Checks local cache first, falls back to live recon."""
    domain = extract_domain_from_email(email_address)
    if not domain:
        return {"error": "Invalid domain"}

    init_domain_cache()
    
    # --- Check Offline Cache First ---
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT intel_data FROM domain_cache WHERE domain = ?", (domain,))
    row = cursor.fetchone()
    
    if row:
        conn.close()
        cached_data = json.loads(row["intel_data"])
        cached_data["status"] = "CACHED"
        return cached_data

    # --- Check Connectivity ---
    if not check_internet_connection():
        print(f"[*] System is offline. Cannot perform live recon for {domain}.")
        conn.close()
        return {"domain": domain, "status": "OFFLINE", "error": "System air-gapped or offline."}

    # --- Cache Miss & Online: Perform Live Recon ---
    print(f"[*] Cache miss for {domain}. Performing live DNS/WHOIS recon...")
    intel_data = perform_live_recon(domain)
    
    # --- Save to Cache ---
    cursor.execute(
        "INSERT OR REPLACE INTO domain_cache (domain, intel_data) VALUES (?, ?)", 
        (domain, json.dumps(intel_data))
    )
    conn.commit()
    conn.close()
    
    return intel_data