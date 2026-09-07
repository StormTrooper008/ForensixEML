import dns.resolver
import re
from typing import Dict, Any, Optional
from logic.parser import verify_dkim


def extract_domain(email_address: str) -> str:
    """Extracts domain from an email address string."""
    match = re.search(r"@([\w.-]+)", email_address)
    return match.group(1).strip().lower() if match else ""


def check_spf_record(domain: str, origin_ip: str) -> Dict[str, Any]:
    """Queries DNS for SPF TXT records and accounts for common include providers."""
    if not domain:
        return {"status": "ERROR", "details": "No domain found", "raw_spf": None}

    try:
        answers = dns.resolver.resolve(domain, "TXT")
        spf_records = [
            r.to_text().strip('"')
            for r in answers
            if "v=spf1" in r.to_text()
        ]

        if not spf_records:
            return {
                "status": "MISSING",
                "details": "No SPF TXT record published by sender domain",
                "raw_spf": None,
            }

        raw_spf = spf_records[0]

        # 1. Exact match
        if origin_ip and origin_ip in raw_spf:
            return {
                "status": "PASS",
                "details": f"Origin IP explicitly authorized in SPF record.",
                "raw_spf": raw_spf,
            }

        # 2. Delegated provider check (Google Workspace, Microsoft 365, Amazon SES, etc.)
        delegated_providers = ["google.com", "outlook.com", "spf.protection", "amazonses.com", "sendgrid.net"]
        for provider in delegated_providers:
            if provider in raw_spf.lower():
                return {
                    "status": "PASS (Delegated)",
                    "details": f"Domain delegates outbound mail to trusted relay ({provider}).",
                    "raw_spf": raw_spf,
                }

        # 3. SoftFail / Neutral default
        return {
            "status": "NEUTRAL",
            "details": "SPF record found with indirect routing mechanisms.",
            "raw_spf": raw_spf,
        }

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return {
            "status": "FAIL",
            "details": "Domain does not exist or has no DNS TXT records",
            "raw_spf": None,
        }
    except Exception as e:
        return {"status": "ERROR", "details": str(e), "raw_spf": None}


def check_dmarc_policy(domain: str) -> Dict[str, Any]:
    """Queries DNS for the _dmarc TXT record and extracts policy."""
    if not domain:
        return {"policy": "NONE", "status": "ERROR", "details": "No domain provided", "raw_dmarc": None}

    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for record in answers:
            txt = record.to_text().strip('"')
            if "v=DMARC1" in txt:
                policy_match = re.search(r"p=(none|quarantine|reject)", txt, re.IGNORECASE)
                policy = policy_match.group(1).upper() if policy_match else "UNSPECIFIED"
                return {
                    "status": "FOUND",
                    "policy": policy,
                    "raw_dmarc": txt,
                    "details": f"DMARC policy set to {policy}.",
                }

        return {
            "status": "MISSING",
            "policy": "NONE",
            "raw_dmarc": None,
            "details": "No DMARC record registered in DNS.",
        }
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return {
            "status": "MISSING",
            "policy": "NONE",
            "raw_dmarc": None,
            "details": "No DMARC record registered in DNS.",
        }
    except Exception as e:
        return {"status": "ERROR", "policy": "ERROR", "details": str(e), "raw_dmarc": None}


def run_protocol_checks(from_header: str, origin_ip: str, raw_bytes: Optional[bytes] = None) -> Dict[str, Any]:
    domain = extract_domain(from_header)
    spf_result = check_spf_record(domain, origin_ip)
    dmarc_result = check_dmarc_policy(domain)
    
    # Run DKIM if the raw email bytes are provided
    if raw_bytes:
        dkim_result = verify_dkim(raw_bytes)
    else:
        dkim_result = {"status": "UNCHECKED", "details": "Raw email bytes not passed to authentication engine."}

    return {
        "domain": domain,
        "spf": spf_result,
        "dmarc": dmarc_result,
        "dkim": dkim_result,
    }