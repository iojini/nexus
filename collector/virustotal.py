"""
VirusTotal collector - fetches recent malicious file reports
https://www.virustotal.com/
Requires free API key from https://www.virustotal.com/gui/join-us
"""

import requests
from datetime import datetime, timezone
import os


def collect(api_key=None):
    """Fetch popular malicious files from VirusTotal"""
    
    api_key = api_key or os.getenv("VT_API_KEY")
    
    if not api_key:
        print("[VirusTotal] No API key found. Set VT_API_KEY environment variable.")
        print("[VirusTotal] Get a free key at: https://www.virustotal.com/gui/join-us")
        return []
    
    # Get popular (trending) malicious files
    url = "https://www.virustotal.com/api/v3/popular_threat_categories"
    headers = {"x-apikey": api_key}
    
    try:
        # First, get some recent malicious file hashes via search
        search_url = "https://www.virustotal.com/api/v3/intelligence/search"
        params = {"query": "type:file positives:5+ fs:7d-", "limit": 20}
        
        response = requests.get(search_url, headers=headers, params=params, timeout=30)
        
        # Free API doesn't have intelligence search, use file feed instead
        if response.status_code == 403:
            print("[VirusTotal] Free API - using limited endpoint")
            return collect_free_tier(api_key)
        
        response.raise_for_status()
        data = response.json()
        
        results = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            results.append({
                "source": "virustotal",
                "type": "sha256",
                "value": item.get("id"),
                "threat_type": "malware",
                "malware_names": attrs.get("popular_threat_classification", {}).get("suggested_threat_label"),
                "detection_ratio": f"{attrs.get('last_analysis_stats', {}).get('malicious', 0)}/{sum(attrs.get('last_analysis_stats', {}).values())}",
                "collected_at": datetime.now(timezone.utc).isoformat()
            })
        
        print(f"[VirusTotal] Collected {len(results)} malicious files")
        return results
        
    except requests.RequestException as e:
        print(f"[VirusTotal] Error: {e}")
        return []


def collect_free_tier(api_key):
    """Fallback for free tier - lookup known malicious hashes"""
    
    # We'll use this to enrich hashes we already have
    # For now, return empty - VT is better used for enrichment
    print("[VirusTotal] Free tier active - use for IOC enrichment instead")
    return []


if __name__ == "__main__":
    iocs = collect()
    for ioc in iocs[:5]:
        print(ioc)
