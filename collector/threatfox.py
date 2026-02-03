"""
ThreatFox collector - fetches IOCs with malware family context
https://threatfox.abuse.ch/
Uses the public JSON feed (no API key required)
"""

import requests
from datetime import datetime, timezone


def collect():
    """Fetch recent IOCs from ThreatFox public feed"""
    
    # Public feed - recent IOCs (last 48 hours)
    url = "https://threatfox.abuse.ch/export/json/recent/"
    
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
        
        results = []
        # Data is nested under date keys
        for date_key, iocs in data.items():
            if not isinstance(iocs, list):
                continue
            for item in iocs:
                results.append({
                    "source": "threatfox",
                    "type": item.get("ioc_type"),
                    "value": item.get("ioc_value"),
                    "threat_type": item.get("threat_type"),
                    "malware": item.get("malware"),
                    "confidence": item.get("confidence_level"),
                    "tags": item.get("tags").split(",") if item.get("tags") else [],
                    "first_seen": item.get("first_seen"),
                    "collected_at": datetime.now(timezone.utc).isoformat()
                })
        
        # Limit to 100
        results = results[:100]
        
        print(f"[ThreatFox] Collected {len(results)} IOCs")
        return results
        
    except requests.RequestException as e:
        print(f"[ThreatFox] Error: {e}")
        return []


if __name__ == "__main__":
    iocs = collect()
    for ioc in iocs[:5]:
        print(ioc)
