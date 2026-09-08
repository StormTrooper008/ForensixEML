import ipaddress
import os
import geoip2.database
from geoip2.errors import AddressNotFoundError
from typing import Dict, Any, List

# Define paths to your new local databases
CITY_DB_PATH = os.path.join("databases", "GeoLite2-City.mmdb")
ASN_DB_PATH = os.path.join("databases", "GeoLite2-ASN.mmdb")

def is_public_ip(ip_str: str) -> bool:
    """Verifies whether an IP is globally routable over the public internet."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_global and not ip_obj.is_private
    except ValueError:
        return False

def get_ip_geolocation(ip_str: str) -> Dict[str, Any]:
    """Resolves coordinates, ASN, infrastructure type (Cloud/Tor) using OFFLINE MaxMind DBs."""
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

    # Initialize baseline for public IP
    payload = default_payload.copy()
    payload["is_public"] = True
    payload["isp"] = "Unknown ISP"
    payload["org"] = "Unknown Org"
    payload["country"] = "Unknown"
    
    # 1. Fetch City & Coordinate Data (Offline)
    if os.path.exists(CITY_DB_PATH):
        try:
            with geoip2.database.Reader(CITY_DB_PATH) as reader:
                city_response = reader.city(ip_str)
                if city_response.country.name:
                    payload["country"] = city_response.country.name
                if city_response.country.iso_code:
                    payload["country_code"] = city_response.country.iso_code
                if city_response.city.name:
                    payload["city"] = city_response.city.name
                if city_response.location.latitude and city_response.location.longitude:
                    payload["lat"] = float(city_response.location.latitude)
                    payload["lon"] = float(city_response.location.longitude)
        except AddressNotFoundError:
            pass
        except Exception as e:
            print(f"MaxMind City DB Error: {e}")

    # 2. Fetch Provider & ASN Data (Offline)
    if os.path.exists(ASN_DB_PATH):
        try:
            with geoip2.database.Reader(ASN_DB_PATH) as reader:
                asn_response = reader.asn(ip_str)
                if asn_response.autonomous_system_number:
                    payload["asn"] = f"AS{asn_response.autonomous_system_number}"
                if asn_response.autonomous_system_organization:
                    payload["org"] = asn_response.autonomous_system_organization
                    payload["isp"] = asn_response.autonomous_system_organization # Free DB maps org to ISP
        except AddressNotFoundError:
            pass
        except Exception as e:
            print(f"MaxMind ASN DB Error: {e}")

    # 3. Local Cloud / Tor Threat Heuristics
    check_str = f"{payload['isp']} {payload['org']} {payload['asn']}".lower()
    
    cloud_keywords = ["digitalocean", "linode", "ovh", "hetzner", "amazon", "aws", "google", "azure"]
    is_cloud = any(k in check_str for k in cloud_keywords)

    tor_keywords = ["tor exit", "tor-exit", "relayon", "mullvad", "vpn"]
    is_tor = any(k in check_str for k in tor_keywords)

    threat_score = 10
    if is_cloud:
        threat_score += 35
    if is_tor:
        threat_score += 60

    payload["is_tor"] = is_tor
    payload["is_cloud"] = is_cloud
    payload["threat_score"] = min(threat_score, 100)
    payload["infra_type"] = "Tor Relay" if is_tor else ("Cloud Hosting" if is_cloud else "Standard ISP")

    return payload

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