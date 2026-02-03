"""
Collector configuration - API endpoints and settings
"""

# Free threat intel feeds (no API key required)
FEEDS = {
    "urlhaus": {
        "name": "URLhaus",
        "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        "type": "malware_urls",
        "format": "json"
    },
    "feodotracker": {
        "name": "Feodo Tracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "type": "botnet_c2",
        "format": "json"
    },
    "threatfox": {
        "name": "ThreatFox",
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "type": "iocs",
        "format": "json"
    }
}

# Sectors we're focusing on (for filtering/tagging)
TARGET_SECTORS = ["healthcare", "retail", "pharmacy"]
