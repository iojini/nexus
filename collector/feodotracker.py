"""
Feodo Tracker collector - fetches botnet C2 server IPs
https://feodotracker.abuse.ch/
"""

import requests
from datetime import datetime, timezone


def collect():
    """Fetch botnet C2 IPs from Feodo Tracker"""
    
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        results = []
        for item in data:
            results.append({
                "source": "feodotracker",
                "type": "ip",
                "value": item.get("ip_address"),
                "port": item.get("port"),
                "threat_type": "botnet_c2",
                "malware": item.get("malware"),
                "first_seen": item.get("first_seen"),
                "last_online": item.get("last_online"),
                "collected_at": datetime.now(timezone.utc).isoformat()
            })
        
        print(f"[FeodoTracker] Collected {len(results)} botnet C2 IPs")
        return results
        
    except requests.RequestException as e:
        print(f"[FeodoTracker] Error: {e}")
        return []


if __name__ == "__main__":
    iocs = collect()
    for ioc in iocs[:5]:
        print(ioc)
