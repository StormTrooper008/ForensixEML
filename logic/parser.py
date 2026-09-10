import email
from email import policy
from email.utils import getaddresses
from email.message import EmailMessage
import ipaddress
import dkim
import re
import hashlib
from typing import Any, Dict, List, Optional
from email.utils import parsedate_to_datetime
import datetime

# High-risk executable and script extensions
HIGH_RISK_EXTENSIONS = {
    '.exe', '.scr', '.vbs', '.bat', '.cmd', '.js', '.iso', '.msi', 
    '.pif', '.wsf', '.jar', '.docm', '.xlsm', '.pptm', '.hta', '.ps1',
    '.cpl', '.reg', '.cab', '.dmg', '.pkg', '.7z', '.rar'
}

def classify_ip_scope(ip_str: str) -> Dict[str, Any]:
    """Classifies an IP address as Public, RFC 1918 Private, Loopback, or Special."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private:
            return {"is_public": False, "scope": "RFC_1918_INTERNAL", "label": "Private / Internal LAN"}
        elif ip_obj.is_loopback:
            return {"is_public": False, "scope": "LOOPBACK", "label": "Localhost / Loopback"}
        elif ip_obj.is_reserved or ip_obj.is_link_local:
            return {"is_public": False, "scope": "SPECIAL", "label": "Reserved / Link-Local"}
        else:
            return {"is_public": True, "scope": "PUBLIC_INTERNET", "label": "Public Routable Internet"}
    except ValueError:
        return {"is_public": False, "scope": "INVALID", "label": "Invalid IP"}

def extract_plain_text(msg: EmailMessage) -> str:
    """Extracts readable plain text body using modern EmailMessage API."""
    text_content = []
    for part in msg.walk():
        ctype = part.get_content_type()
        cdisp = str(part.get("Content-Disposition", ""))
        if ctype == "text/plain" and "attachment" not in cdisp:
            try:
                content = part.get_content()
                if content:
                    text_content.append(str(content))
            except Exception:
                continue
    return "\n".join(text_content).strip()

def extract_html_content(msg: EmailMessage) -> str:
    """Extracts raw HTML payload if present."""
    html_parts = []
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            try:
                content = part.get_content()
                if content:
                    html_parts.append(str(content))
            except Exception:
                continue
    return "\n".join(html_parts).strip()

def extract_attachments_telemetry(msg: EmailMessage) -> list:
    """Walks all multipart boundaries, calculates SHA256 hashes, and flags risky extensions."""
    attachments = []
    for part in msg.walk():
        cdisp = str(part.get("Content-Disposition", ""))
        fname = part.get_filename()
        
        # Identify if the part is an attachment
        if fname or "attachment" in cdisp.lower():
            raw_payload = part.get_payload(decode=True)
            
            # Force strictly into bytes to satisfy type checkers and hashlib
            if raw_payload is None:
                payload_bytes = b""
            elif isinstance(raw_payload, str):
                payload_bytes = raw_payload.encode('utf-8', errors='ignore')
            else:
                payload_bytes = bytes(raw_payload)
                
            size_b = len(payload_bytes)
            sha256 = hashlib.sha256(payload_bytes).hexdigest() if size_b > 0 else "EMPTY"
            ext = ("." + fname.split(".")[-1].lower()) if (fname and "." in fname) else ""
            
            attachments.append({
                "filename": fname or "unnamed_payload",
                "extension": ext,
                "size_kb": round(size_b / 1024, 2),
                "sha256": sha256,
                "is_risky": ext in HIGH_RISK_EXTENSIONS,
                "content_type": part.get_content_type()
            })
    return attachments

def parse_step1_headers(eml_bytes: bytes) -> Dict[str, Any]:
    """Core function for Step 1: Takes raw email bytes and performs complete decomposition."""
    msg = email.message_from_bytes(eml_bytes, policy=policy.default)

    # 1. Identity & Routing Headers
    from_header = msg.get("From", "None")
    return_path = msg.get("Return-Path", "None")
    reply_to = msg.get("Reply-To", "None")
    subject = msg.get("Subject", "(No Subject)")
    date = msg.get("Date", "None")
    message_id = msg.get("Message-ID", "None")
    
    to_header = msg.get("To", "")
    cc_header = msg.get("Cc", "")
    bcc_header = msg.get("Bcc", "")

    recipients = []
    for name, addr in getaddresses([to_header]):
        if addr: recipients.append({"name": name.strip() or "Unknown", "email": addr.lower(), "type": "TO"})
    for name, addr in getaddresses([cc_header]):
        if addr: recipients.append({"name": name.strip() or "Unknown", "email": addr.lower(), "type": "CC"})
    for name, addr in getaddresses([bcc_header]):
        if addr: recipients.append({"name": name.strip() or "Unknown", "email": addr.lower(), "type": "BCC"})

    # 2. Extract and Order Hops Chronologically (WITH TRANSIT DELAYS)
    raw_received = msg.get_all("Received", [])
    ip_regex = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    hops: List[Dict[str, Any]] = []
    origin_candidate: Optional[Dict[str, Any]] = None
    
    previous_time = None

    for hop_index, header_value in enumerate(reversed(raw_received), start=1):
        clean_header = header_value.strip().replace("\n", " ").replace("\t", " ")
        found_ips = re.findall(ip_regex, clean_header)
        
        # --- NEW: Extract and calculate transit timestamps ---
        hop_time = None
        delay_seconds = 0
        timestamp_str = "Unknown"
        
        if ";" in clean_header:
            try:
                # The timestamp is almost always after the last semicolon in a Received header
                time_part = clean_header.rsplit(";", 1)[-1].strip()
                hop_time = parsedate_to_datetime(time_part)
                timestamp_str = hop_time.isoformat()
                
                if previous_time and hop_time >= previous_time:
                    delay_seconds = int((hop_time - previous_time).total_seconds())
                
                previous_time = hop_time
            except Exception:
                pass # Unparseable or malformed date string

        hop_details = {
            "hop_number": hop_index, 
            "raw_text": clean_header, 
            "extracted_ips": [],
            "timestamp": timestamp_str,
            "delay_seconds": delay_seconds
        }

        for ip in found_ips:
            classification = classify_ip_scope(ip)
            hop_details["extracted_ips"].append({"ip": ip, "classification": classification})

            if origin_candidate is None and classification["scope"] == "PUBLIC_INTERNET":
                origin_candidate = {
                    "ip": ip,
                    "scope": classification["scope"],
                    "label": classification["label"],
                    "hop_discovered": hop_index,
                }
        hops.append(hop_details)

    # 3. Message Body & Attachments
    body_text = extract_plain_text(msg)
    body_html = extract_html_content(msg)
    attachments = extract_attachments_telemetry(msg)
    has_risky_attachments = any(att["is_risky"] for att in attachments)

    return {
        "headers": {
            "Subject": subject, "From": from_header, "Return-Path": return_path,
            "Reply-To": reply_to, "To": to_header, "Cc": cc_header,
            "Date": date, "Message-ID": message_id,
        },
        "recipients": recipients,
        "recipient_count": len(recipients),
        "hops": hops,
        "total_hops": len(hops),
        "origin_candidate": origin_candidate or {"ip": "Unknown", "scope": "NONE", "label": "No IP extracted"},
        "body_full": body_text,
        "body_html": body_html,
        "body_preview": (body_text[:180] + "..." if len(body_text) > 180 else body_text),
        "attachments": attachments,
        "has_risky_attachments": has_risky_attachments
    }

def verify_dkim(raw_email_bytes):
    """Validates the DKIM cryptographic signature using the sender's public DNS records."""
    if not raw_email_bytes:
        return {"status": "UNCHECKED", "details": "No raw email bytes provided for DKIM verification."}
    try:
        is_valid = dkim.verify(raw_email_bytes)
        if is_valid:
            return {"status": "PASS", "details": "Cryptographic seal is intact. Content unmodified."}
        else:
            return {"status": "FAIL / MISSING", "details": "Signature broken, tampered, or not present."}
    except Exception as e:
        return {"status": "ERROR", "details": f"DKIM check failed: {e}"}