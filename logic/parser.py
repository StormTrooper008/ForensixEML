import email
from email import policy
from email.message import EmailMessage  # <-- Add this explicit import
import ipaddress
import dkim
import re
from typing import Any, Dict, List, Optional


def classify_ip_scope(ip_str: str) -> Dict[str, Any]:
    """Classifies an IP address as Public, RFC 1918 Private, Loopback, or Special."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private:
            return {
                "is_public": False,
                "scope": "RFC_1918_INTERNAL",
                "label": "Private / Internal LAN",
            }
        elif ip_obj.is_loopback:
            return {
                "is_public": False,
                "scope": "LOOPBACK",
                "label": "Localhost / Loopback",
            }
        elif ip_obj.is_reserved or ip_obj.is_link_local:
            return {
                "is_public": False,
                "scope": "SPECIAL",
                "label": "Reserved / Link-Local",
            }
        else:
            return {
                "is_public": True,
                "scope": "PUBLIC_INTERNET",
                "label": "Public Routable Internet",
            }
    except ValueError:
        return {"is_public": False, "scope": "INVALID", "label": "Invalid IP"}


def extract_plain_text(msg: EmailMessage) -> str:
    """Extracts readable plain text body using modern EmailMessage API."""
    text_content = []
    
    # msg.walk() automatically handles both single-part and multipart emails
    for part in msg.walk():
        ctype = part.get_content_type()
        cdisp = str(part.get("Content-Disposition", ""))
        
        # Look for text parts that aren't file attachments
        if ctype == "text/plain" and "attachment" not in cdisp:
            try:
                # get_content() automatically handles bytes, strings, and charset decoding!
                content = part.get_content()
                if content:
                    text_content.append(str(content))
            except Exception:
                continue

    return "\n".join(text_content).strip()


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

    # 2. Extract and Order Hops Chronologically (Bottom to Top)
    raw_received = msg.get_all("Received", [])
    ip_regex = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

    hops: List[Dict[str, Any]] = []
    origin_candidate: Optional[Dict[str, Any]] = None

    # Reverse to trace sequence: Origin -> Intermediate Relays -> Recipient
    for hop_index, header_value in enumerate(reversed(raw_received), start=1):
        clean_header = (
            header_value.strip().replace("\n", " ").replace("\t", " ")
        )
        found_ips = re.findall(ip_regex, clean_header)

        hop_details = {
            "hop_number": hop_index,
            "raw_text": clean_header,
            "extracted_ips": [],
        }

        for ip in found_ips:
            classification = classify_ip_scope(ip)
            ip_info = {"ip": ip, "classification": classification}
            hop_details["extracted_ips"].append(ip_info)

            # Earliest public or internal IP discovered is marked as the origin candidate
            # Strictly hunt for the earliest PUBLIC IP (skipping internal network routing)
            if origin_candidate is None and classification["scope"] == "PUBLIC_INTERNET":
                origin_candidate = {
                    "ip": ip,
                    "scope": classification["scope"],
                    "label": classification["label"],
                    "hop_discovered": hop_index,
                }

        hops.append(hop_details)

    # 3. Message Body
    body_text = extract_plain_text(msg)

    return {
        "headers": {
            "Subject": subject,
            "From": from_header,
            "Return-Path": return_path,
            "Reply-To": reply_to,
            "Date": date,
            "Message-ID": message_id,
        },
        "hops": hops,
        "total_hops": len(hops),
        "origin_candidate": origin_candidate
        or {"ip": "Unknown", "scope": "NONE", "label": "No IP extracted"},
        "body_full": body_text,  # <-- ADD THIS NEW LINE
        "body_preview": (
            body_text[:180] + "..." if len(body_text) > 180 else body_text
        ),
    }


if __name__ == "__main__":
    import json
    import os

    sample_path = os.path.join("data", "sample.eml")
    if os.path.exists(sample_path):
        with open(sample_path, "rb") as f:
            output = parse_step1_headers(f.read())
            print(json.dumps(output, indent=2))
    else:
        print(f"Error: {sample_path} not found. Please create it first.")

def verify_dkim(raw_email_bytes):
    """
    Validates the DKIM cryptographic signature using the sender's public DNS records.
    Requires the raw, unparsed byte string of the .eml file.
    """
    # --- BULLETPROOF GUARD FOR NONE OR EMPTY BYTES ---
    if not raw_email_bytes:
        return {"status": "UNCHECKED", "details": "No raw email bytes provided for DKIM verification."}
    
    try:
        # dkim.verify reads the bytes, fetches the public key from DNS, and does the math
        is_valid = dkim.verify(raw_email_bytes)
        
        if is_valid:
            return {"status": "PASS", "details": "Cryptographic seal is intact. Content unmodified."}
        else:
            return {"status": "FAIL / MISSING", "details": "Signature broken, tampered, or not present."}
    except Exception as e:
        return {"status": "ERROR", "details": f"DKIM check failed: {e}"}