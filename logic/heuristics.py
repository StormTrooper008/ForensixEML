import re
from typing import Dict, Any, List

def scan_body_heuristics(body_text: str) -> Dict[str, Any]:
    """Scans plain text for malicious URLs and urgency keywords."""
    if not body_text:
        return {"urls": [], "keywords": [], "score": 0}

    urls: List[str] = re.findall(r'(https?://[^\s]+)', body_text)
    
    trigger_words = ["urgent", "verify", "suspend", "immediate", "password", "invoice", "bank"]
    found_keywords = [kw for kw in trigger_words if kw in body_text.lower()]

    penalty = (len(urls) * 5) + (len(found_keywords) * 10)
    
    return {
        "urls": urls,
        "keywords": found_keywords,
        "score": min(penalty, 100) 
    }