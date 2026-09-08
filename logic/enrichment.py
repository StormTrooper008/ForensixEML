import ipaddress
import requests
from typing import Dict, Any, List

def is_public_ip(ip_str: str) -> bool:
    """Verifies whether an IP is globally routable over the public internet."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_global and not ip_obj.is_private
    except ValueError:
        return False

def get_ip_geolocation(ip_str: str) -> Dict[str, Any]:
    """Resolves coordinates, ASN, infrastructure type (Cloud/Tor)."""
    default_payload = {
        "ip": ip_str,
        "country": "Unknown / Internal",
        "country_code": "--",
        "city": "Unknown",
        "lat": 20.0,
        "lon": 0.0,
        "isp": "Local Area Network / Unrouted",
        "org": "N/A",
        "asn": "N/A",
        "infra_type": "Internal / Private",
        "is_tor": False,
        "is_cloud": False,
        "threat_score": 0,
        "is_public": False,
    }

    if not is_public_ip(ip_str):
        return default_payload

    try:
        # Added hosting and proxy fields to the API query
        url = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,countryCode,city,lat,lon,isp,org,as,hosting,proxy"
        response = requests.get(url, timeout=4)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                isp = data.get("isp") or ""
                org = data.get("org") or ""
                asn = data.get("as") or "Unknown ASN"
                check_str = f"{isp} {org} {asn}".lower()

                # Cloud / Data Center Hosting Detection
                cloud_keywords = ["digitalocean", "linode", "ovh", "hetzner", "amazon", "aws", "google", "azure"]
                is_cloud = bool(data.get("hosting")) or any(k in check_str for k in cloud_keywords)

                # Tor / Proxy Detection
                tor_keywords = ["tor exit", "tor-exit", "relayon", "mullvad", "vpn"]
                is_tor = bool(data.get("proxy")) or any(k in check_str for k in tor_keywords)

                # Threat Score Calibration
                threat_score = 10
                if is_cloud:
                    threat_score += 35
                if is_tor:
                    threat_score += 60

                infra_type = "Tor Relay" if is_tor else ("Cloud Hosting" if is_cloud else "Standard ISP")

                return {
                    "ip": ip_str,
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "--"),
                    "city": data.get("city", "Unknown"),
                    "lat": float(data.get("lat", 0.0)),
                    "lon": float(data.get("lon", 0.0)),
                    "isp": isp or "Unknown ISP",
                    "org": org or "Unknown Org",
                    "asn": asn,
                    "infra_type": infra_type,
                    "is_tor": is_tor,
                    "is_cloud": is_cloud,
                    "threat_score": min(threat_score, 100),
                    "is_public": True,
                }
    except Exception:
        pass

    default_payload["is_public"] = True
    return default_payload

def enrich_hop_chain(hops: list) -> list:
    """Iterates through extracted hops and enriches public IPs with Geo/ASN data."""
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