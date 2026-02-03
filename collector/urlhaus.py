"""
URLhaus collector - fetches recent malicious URLs
https://urlhaus.abuse.ch/
Uses the public CSV feed (no API key required)
"""

import requests
import csv
from io import StringIO
from datetime import datetime, timezone


def collect():
    """Fetch recent malicious URLs from URLhaus public feed"""
    
    # Public feed - online URLs only (no auth required)
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        
        # Skip comment lines (start with #)
        lines = [line for line in response.text.split('\n') if not line.startswith('#') and line.strip()]
        
        reader = csv.reader(lines)
        
        results = []
        for row in reader:
            if len(row) >= 8:
                results.append({
                    "source": "urlhaus",
                    "type": "url",
                    "value": row[2],  # url
                    "url_status": row[3],  # online/offline
                    "threat_type": row[5],  # threat type
                    "tags": row[6].split(",") if row[6] else [],
                    "date_added": row[1],
                    "collected_at": datetime.now(timezone.utc).isoformat()
                })
        
        # Limit to most recent 100
        results = results[:100]
        
        print(f"[URLhaus] Collected {len(results)} malicious URLs")
        return results
        
    except requests.RequestException as e:
        print(f"[URLhaus] Error: {e}")
        return []


if __name__ == "__main__":
    iocs = collect()
    for ioc in iocs[:5]:  # Print first 5 as sample
        print(ioc)
