"""
Shodan collector - fetches exposed/vulnerable devices
https://www.shodan.io/
Requires free API key from https://account.shodan.io/
"""

import requests
from datetime import datetime, timezone
import os


def collect(api_key=None):
    """Fetch recent vulnerable devices from Shodan"""
    
    api_key = api_key or os.getenv("SHODAN_API_KEY")
    
    if not api_key:
        print("[Shodan] No API key found. Set SHODAN_API_KEY environment variable.")
        print("[Shodan] Get a free key at: https://account.shodan.io/")
        return []
    
    # Search for healthcare/retail related vulnerable systems
    queries = [
        "healthcare vuln",
        "pharmacy",
        "pos system",
    ]
    
    results = []
    
    try:
        for query in queries[:1]:  # Limit to 1 query on free tier
            url = "https://api.shodan.io/shodan/host/search"
            params = {
                "key": api_key,
                "query": query,
                "limit": 20
            }
            
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 401:
                print("[Shodan] Invalid API key")
                return []
            elif response.status_code == 403:
                print("[Shodan] Free tier - limited queries")
                # Try a simpler endpoint
                return collect_free_tier(api_key)
            
            response.raise_for_status()
            data = response.json()
            
            for item in data.get("matches", []):
                results.append({
                    "source": "shodan",
                    "type": "ip",
                    "value": item.get("ip_str"),
                    "port": item.get("port"),
                    "threat_type": "exposed_service",
                    "product": item.get("product"),
                    "org": item.get("org"),
                    "country": item.get("location", {}).get("country_name"),
                    "vulns": list(item.get("vulns", {}).keys()) if item.get("vulns") else [],
                    "collected_at": datetime.now(timezone.utc).isoformat()
                })
        
        print(f"[Shodan] Collected {len(results)} exposed devices")
        return results
        
    except requests.RequestException as e:
        print(f"[Shodan] Error: {e}")
        return []


def collect_free_tier(api_key):
    """Fallback for free tier - get API info only"""
    print("[Shodan] Free tier active - use for IOC enrichment instead")
    return []


if __name__ == "__main__":
    iocs = collect()
    for ioc in iocs[:5]:
        print(ioc)
