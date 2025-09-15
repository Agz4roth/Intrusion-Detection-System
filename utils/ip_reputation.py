import ipaddress

def score_ip(ip: str) -> int:
    """
    Mock reputation scoring: 0 (bad) to 100 (good).
    You can later integrate with AbuseIPDB/VirusTotal/etc.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return 50
    # Simple heuristic: private ranges get neutral, others slight bias
    if addr.is_private:
        return 60
    if addr.is_loopback:
        return 70
    if addr.is_multicast:
        return 40
    return 65
