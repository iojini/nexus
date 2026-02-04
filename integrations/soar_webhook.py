"""
SOAR Webhook Integration - sends alerts to SOAR platforms via webhooks
Compatible with: Cortex XSOAR, Splunk SOAR, TheHive, Shuffle, Tines
"""

import requests
import json
from datetime import datetime, timezone
from typing import List, Dict, Optional
import os


class SOARWebhook:
    """Generic SOAR webhook integration"""
    
    def __init__(self, webhook_url: str = None, api_key: str = None):
        """
        Initialize SOAR webhook
        
        Args:
            webhook_url: Webhook endpoint URL
            api_key: Optional API key for authentication
        """
        self.webhook_url = webhook_url or os.getenv("SOAR_WEBHOOK_URL")
        self.api_key = api_key or os.getenv("SOAR_API_KEY")
    
    def send_incident(self, incident: Dict) -> Dict:
        """
        Send an incident to SOAR platform
        
        Args:
            incident: Incident dictionary with required fields
        """
        if not self.webhook_url:
            return {"status": "error", "message": "Webhook URL not configured"}
        
        payload = {
            "source": "HRTIP",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "incident": incident
        }
        
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        try:
            response = requests.post(
                self.webhook_url,
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code in [200, 201, 202]:
                return {"status": "success", "response": response.text}
            else:
                return {"status": "error", "code": response.status_code, "message": response.text}
                
        except requests.RequestException as e:
            return {"status": "error", "message": str(e)}
    
    def create_incident_from_cluster(self, cluster: Dict, iocs: List[Dict] = None) -> Dict:
        """Create a SOAR incident from a threat cluster"""
        
        incident = {
            "title": f"Campaign Detected: {cluster.get('potential_campaign', 'Unknown')}",
            "severity": self._calculate_severity(cluster),
            "type": "Threat Campaign",
            "description": self._build_description(cluster),
            "indicators": iocs or cluster.get("sample_iocs", []),
            "mitre_attack": {
                "tactics": cluster.get("threat_types", []),
                "techniques": []
            },
            "metadata": {
                "cluster_id": cluster.get("cluster_id"),
                "ioc_count": cluster.get("size", 0),
                "sources": cluster.get("sources", []),
                "malware_families": cluster.get("malware_families", [])
            },
            "recommended_actions": [
                "Block all identified IOCs at network perimeter",
                "Search for historical matches in SIEM",
                "Isolate any affected endpoints",
                "Collect forensic artifacts if compromise confirmed"
            ]
        }
        
        return self.send_incident(incident)
    
    def create_incident_from_anomaly(self, anomaly: Dict) -> Dict:
        """Create a SOAR incident from an anomalous IOC"""
        
        incident = {
            "title": f"Anomalous Indicator Detected: {anomaly.get('value', 'Unknown')}",
            "severity": "medium" if anomaly.get("anomaly", {}).get("anomaly_score", 0) < 80 else "high",
            "type": "Anomaly Detection",
            "description": f"ML-based anomaly detection flagged this {anomaly.get('type')} indicator as unusual",
            "indicators": [anomaly.get("value")],
            "metadata": {
                "ioc_type": anomaly.get("type"),
                "source": anomaly.get("source"),
                "anomaly_score": anomaly.get("anomaly", {}).get("anomaly_score"),
                "threat_type": anomaly.get("threat_type")
            },
            "recommended_actions": [
                "Investigate the indicator manually",
                "Check for related activity in logs",
                "Determine if this is a new threat or false positive"
            ]
        }
        
        return self.send_incident(incident)
    
    def _calculate_severity(self, cluster: Dict) -> str:
        """Calculate incident severity based on cluster attributes"""
        
        size = cluster.get("size", 0)
        threat_types = cluster.get("threat_types", [])
        malware = cluster.get("malware_families", [])
        
        # Critical if ransomware or large campaign
        if "ransomware" in threat_types or size > 20:
            return "critical"
        # High if botnet C2 or known malware
        if "botnet_c2" in threat_types or malware:
            return "high"
        # Medium for phishing
        if "phishing" in threat_types:
            return "medium"
        
        return "low"
    
    def _build_description(self, cluster: Dict) -> str:
        """Build incident description from cluster data"""
        
        parts = [
            f"Threat Intelligence Platform detected a potential {cluster.get('potential_campaign', 'threat campaign')}.",
            f"\nCluster contains {cluster.get('size', 0)} related indicators.",
        ]
        
        if cluster.get("malware_families"):
            parts.append(f"\nMalware families: {', '.join(cluster['malware_families'])}")
        
        if cluster.get("threat_types"):
            parts.append(f"\nThreat types: {', '.join(cluster['threat_types'])}")
        
        if cluster.get("sources"):
            parts.append(f"\nSources: {', '.join(cluster['sources'])}")
        
        return "".join(parts)
    
    def generate_thehive_alert(self, iocs: List[Dict], title: str = "HRTIP Threat Alert") -> Dict:
        """
        Generate TheHive-compatible alert format
        
        Can be sent to TheHive's webhook or API
        """
        return {
            "title": title,
            "description": f"Threat intelligence alert containing {len(iocs)} indicators",
            "severity": 2,  # 1=Low, 2=Medium, 3=High
            "tlp": 2,       # TLP:AMBER
            "pap": 2,       # PAP:AMBER
            "tags": ["hrtip", "threat-intel"],
            "type": "external",
            "source": "HRTIP",
            "sourceRef": f"hrtip-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "artifacts": [
                {
                    "dataType": self._map_ioc_type(ioc.get("type")),
                    "data": ioc.get("value"),
                    "message": f"Source: {ioc.get('source')}, Threat: {ioc.get('threat_type')}",
                    "tags": [ioc.get("malware")] if ioc.get("malware") else []
                }
                for ioc in iocs
            ]
        }
    
    def _map_ioc_type(self, ioc_type: str) -> str:
        """Map HRTIP IOC types to TheHive artifact types"""
        mapping = {
            "ipv4": "ip",
            "domain": "domain",
            "url": "url",
            "md5": "hash",
            "sha256": "hash",
            "sha1": "hash",
            "email": "mail"
        }
        return mapping.get(ioc_type, "other")


if __name__ == "__main__":
    print("=" * 60)
    print("SOAR Webhook Integration - Demo")
    print("=" * 60)
    
    soar = SOARWebhook()
    
    # Demo cluster
    test_cluster = {
        "cluster_id": 1,
        "potential_campaign": "Emotet Botnet Campaign",
        "size": 15,
        "threat_types": ["botnet_c2"],
        "malware_families": ["Emotet"],
        "sources": ["feodotracker", "threatfox"],
        "sample_iocs": ["45.33.32.156", "162.243.103.246"]
    }
    
    # Demo IOCs
    test_iocs = [
        {"type": "ipv4", "value": "45.33.32.156", "source": "feodotracker", "threat_type": "botnet_c2", "malware": "Emotet"},
        {"type": "domain", "value": "evil-phish.xyz", "source": "openphish", "threat_type": "phishing"},
    ]
    
    print("\nGenerated TheHive Alert:")
    print("-" * 40)
    thehive_alert = soar.generate_thehive_alert(test_iocs, "Emotet Campaign Detected")
    print(json.dumps(thehive_alert, indent=2))
    
    print("\n" + "-" * 40)
    if not soar.webhook_url:
        print("Note: SOAR_WEBHOOK_URL not configured")
        print("Set environment variables to enable live integration:")
        print("  export SOAR_WEBHOOK_URL=https://your-soar/webhook")
        print("  export SOAR_API_KEY=your-api-key")
