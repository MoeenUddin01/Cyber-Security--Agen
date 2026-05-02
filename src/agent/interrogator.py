"""IP Intelligence Interrogator for gathering threat actor information."""

import socket
from ipwhois import IPWhois
import logging

logger = logging.getLogger(__name__)


def interrogate_ip(ip_address: str):
    """Gathers intelligence on a suspicious IP address.
    
    Performs WHOIS lookup to get provider and country information,
    and scans common ports to identify open services.
    
    Args:
        ip_address: The IP address to investigate.
        
    Returns:
        Dictionary containing provider, country, and list of open ports.
    """
    intel = {
        "provider": "Unknown",
        "country": "Unknown",
        "open_services": []
    }
    
    # 1. WHOIS Lookup
    try:
        # Note: In a real-world local network (192.168.x.x), 
        # WHOIS will fail. We handle that gracefully.
        if not ip_address.startswith(("192.168.", "10.", "127.")):
            obj = IPWhois(ip_address)
            results = obj.lookup_rdap()
            intel["provider"] = results.get('asn_description', 'Unknown')
            intel["country"] = results.get('asn_country_code', 'Unknown')
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {ip_address}: {e}")

    # 2. Quick Service Scan (Counter-Intel)
    # We check if the attacker has common control ports open
    ports_to_check = [22, 80, 443, 8080]
    for port in ports_to_check:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)  # Fast scan
            if s.connect_ex((ip_address, port)) == 0:
                intel["open_services"].append(port)
                
    return intel


if __name__ == "__main__":
    # Test the interrogator
    test_ip = "8.8.8.8"  # Google's public DNS
    print(f"Interrogating {test_ip}...")
    result = interrogate_ip(test_ip)
    print(f"Provider: {result['provider']}")
    print(f"Country: {result['country']}")
    print(f"Open Services: {result['open_services']}")
