import ipaddress
import requests
from typing import Dict, Any, Optional


def is_public_ip(ip_str: str) -> bool:
    """Verifies whether an IP is globally routable over the public internet."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_global and not ip_obj.is_private
    except ValueError:
        return False


def get_ip_geolocation(ip_str: str) -> Dict[str, Any]:
    """Resolves coordinates, country, city, and ISP for a public IP address."""
    default_payload = {
        "ip": ip_str,
        "country": "Unknown / Internal",
        "country_code": "--",
        "city": "Unknown",
        "lat": 20.0,
        "lon": 0.0,
        "isp": "Local Area Network / Unrouted",
        "org": "N/A",
        "threat_score": 0,
        "is_public": False,
    }

    if not is_public_ip(ip_str):
        return default_payload

    try:
        # Query free GeoIP lookup endpoint (rate-limited, no API key needed for testing)
        url = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,countryCode,city,lat,lon,isp,org,as,query"
        response = requests.get(url, timeout=4)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                # Basic heuristic threat weighting based on bulletproof hosters / known high-risk ASNs
                isp_lower = (data.get("isp") or "").lower()
                org_lower = (data.get("org") or "").lower()
                threat_score = 15
                if any(k in isp_lower or k in org_lower for k in ["tor", "vpn", "mullvad", "digitalocean", "linode", "ovh"]):
                    threat_score = 65

                return {
                    "ip": ip_str,
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "--"),
                    "city": data.get("city", "Unknown"),
                    "lat": float(data.get("lat", 0.0)),
                    "lon": float(data.get("lon", 0.0)),
                    "isp": data.get("isp", "Unknown ISP"),
                    "org": data.get("org", "Unknown Org"),
                    "threat_score": threat_score,
                    "is_public": True,
                }
    except Exception:
        pass

    default_payload["is_public"] = True
    return default_payload


def enrich_hop_chain(hops: list) -> list:
    """Iterates through extracted hops and enriches any public IPs found with GeoIP data."""
    enriched_hops = []
    for hop in hops:
        hop_copy = dict(hop)
        enriched_ips = []
        for ip_entry in hop.get("extracted_ips", []):
            ip_val = ip_entry.get("ip")
            geo_info = get_ip_geolocation(ip_val)
            ip_combined = {**ip_entry, "geo": geo_info}
            enriched_ips.append(ip_combined)
        hop_copy["extracted_ips"] = enriched_ips
        enriched_hops.append(hop_copy)
    return enriched_hops