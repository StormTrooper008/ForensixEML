import re
from bs4 import BeautifulSoup
from typing import Dict, Any, List

def scan_body_heuristics(body_text: str, html_body: str = "") -> Dict[str, Any]:
    """Scans plain text and HTML for urgency cues, embedded URLs, and Anchor Text vs Hyperlink mismatches."""
    if not body_text and not html_body:
        return {"urls": [], "keywords": [], "link_mismatches": [], "score": 0}

    combined_text = f"{body_text} {html_body}"
    
    # 1. URL Extraction
    urls: List[str] = list(set(re.findall(r'(https?://[^\s<>"]+|www\.[^\s<>"]+)', combined_text)))

    # 2. Urgency Triggers
    trigger_words = [
        "urgent", "verify", "suspend", "immediate", "password", 
        "invoice", "bank", "kyc", "terminated", "compromised", "unauthorized"
    ]
    found_keywords = [kw for kw in trigger_words if kw in combined_text.lower()]

    # 3. Anchor Text vs Hyperlink Destination Mismatch Detection
    link_mismatches = []
    if html_body:
        try:
            soup = BeautifulSoup(html_body, "html.parser")
            
            # --- 1. DEFINE TRACKERS HERE ---
            tracker_domains = ["sendibm1.com", "sendgrid.net", "mailchimp.com", "hubspot.com", "ctctcdn.com"]
            # -------------------------------
            
            for a_tag in soup.find_all("a", href=True):
                raw_href = a_tag.get("href", "")
                if isinstance(raw_href, list):
                    raw_href = " ".join(raw_href)
                href = str(raw_href).strip()
                if not href:
                    continue
                    
                # --- 2. SKIP TRACKERS HERE ---
                if any(tracker in href.lower() for tracker in tracker_domains):
                    continue
                # -----------------------------
                
                anchor_text = a_tag.get_text().strip()
                
                # Check if anchor text looks like a URL or domain
                if re.match(r'^(https?://|www\.)', anchor_text, re.IGNORECASE):
                    href_domain_match = re.search(r'https?://([^/]+)', href, re.IGNORECASE)
                    anchor_domain_match = re.search(r'(?:https?://)?([^/]+)', anchor_text, re.IGNORECASE)
                    
                    if href_domain_match and anchor_domain_match:
                        href_domain = href_domain_match.group(1).lower()
                        anchor_domain = anchor_domain_match.group(1).lower()
                        
                        # The Bait & Switch check
                        if href_domain != anchor_domain:
                            link_mismatches.append({
                                "claimed": anchor_text,
                                "actual": href
                            })
        except Exception:
            pass

    # Risk Penalty Calculation
    penalty = (len(urls) * 5) + (len(found_keywords) * 8) + (len(link_mismatches) * 20)
    
    return {
        "urls": urls,
        "keywords": found_keywords,
        "link_mismatches": link_mismatches,
        "score": min(penalty, 100)
    }