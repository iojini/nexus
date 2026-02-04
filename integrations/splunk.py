"""
Splunk Integration - push IOCs and alerts to Splunk via HEC
"""

import requests
import json
from datetime import datetime, timezone
from typing import List, Dict, Optional
import os


class SplunkHEC:
    """Splunk HTTP Event Collector integration"""
    
    def __init__(self, hec_url: str = None, hec_token: str = None):
        """
        Initialize Splunk HEC connection
        
        Args:
            hec_url: Splunk HEC URL (e.g., https://splunk:8088/services/collector/event)
            hec_token: HEC token for authentication
        """
        self.hec_url = hec_url or os.getenv("SPLUNK_HEC_URL")
        self.hec_token = hec_token or os.getenv("SPLUNK_HEC_TOKEN")
        self.verify_ssl = os.getenv("SPLUNK_VERIFY_SSL", "true").lower() == "true"
    
    def _send_event(self, event: Dict, index: str = "threat_intel", sourcetype: str = "hrtip") -> Dict:
        """Send a single event to Splunk"""
        
        if not self.hec_url or not self.hec_token:
            return {"status": "error", "message": "Splunk HEC not configured"}
        
        payload = {
            "index": index,
            "sourcetype": sourcetype,
            "time": datetime.now(timezone.utc).timestamp(),
            "event": event
        }
        
        headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(
                self.hec_url,
                headers=headers,
                json=payload,
                verify=self.verify_ssl,
                timeout=10
            )
            
            if response.status_code == 200:
                return {"status": "success", "response": response.json()}
            else:
                return {"status": "error", "code": response.status_code, "message": response.text}
                
        except requests.RequestException as e:
            return {"status": "error", "message": str(e)}
    
    def send_iocs(self, iocs: List[Dict], index: str = "threat_intel") -> Dict:
        """
        Send multiple IOCs to Splunk
        
        Args:
            iocs: List of IOC dictionaries
            index: Target Splunk index
        
        Returns:
            Summary of sent events
        """
        results = {"sent": 0, "failed": 0, "errors": []}
        
        for ioc in iocs:
            event = {
                "event_type": "ioc",
                "ioc_type": ioc.get("type"),
                "ioc_value": ioc.get("value"),
                "source": ioc.get("source"),
                "threat_type": ioc.get("threat_type"),
                "malware": ioc.get("malware"),
                "confidence_score": ioc.get("confidence_score"),
                "mitre_techniques": ioc.get("mitre_attack", {}).get("techniques", []),
                "tags": ioc.get("tags", []),
                "enrichment": ioc.get("enrichment", {}),
                "collected_at": ioc.get("collected_at")
            }
            
            result = self._send_event(event, index=index, sourcetype="hrtip:ioc")
            
            if result["status"] == "success":
                results["sent"] += 1
            else:
                results["failed"] += 1
                results["errors"].append(result.get("message", "Unknown error"))
        
        return results
    
    def send_alert(self, alert: Dict, index: str = "threat_intel") -> Dict:
        """
        Send an alert/notable event to Splunk
        
        Args:
            alert: Alert dictionary with title, severity, description, etc.
            index: Target Splunk index
        """
        event = {
            "event_type": "alert",
            "title": alert.get("title"),
            "severity": alert.get("severity", "medium"),
            "description": alert.get("description"),
            "iocs": alert.get("iocs", []),
            "mitre_techniques": alert.get("mitre_techniques", []),
            "recommended_actions": alert.get("recommended_actions", []),
            "source": "HRTIP",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        return self._send_event(event, index=index, sourcetype="hrtip:alert")
    
    def send_cluster_alert(self, cluster: Dict, index: str = "threat_intel") -> Dict:
        """Send a campaign/cluster detection alert"""
        
        alert = {
            "title": f"Threat Campaign Detected: {cluster.get('potential_campaign', 'Unknown')}",
            "severity": "high" if cluster.get("size", 0) > 5 else "medium",
            "description": f"Detected {cluster.get('size', 0)} related IOCs suggesting coordinated threat activity",
            "iocs": cluster.get("sample_iocs", []),
            "mitre_techniques": [],
            "campaign_info": {
                "cluster_id": cluster.get("cluster_id"),
                "threat_types": cluster.get("threat_types", []),
                "malware_families": cluster.get("malware_families", []),
                "sources": cluster.get("sources", [])
            },
            "recommended_actions": [
                "Block identified IOCs at perimeter",
                "Hunt for related indicators in environment",
                "Review logs for historical matches"
            ]
        }
        
        return self.send_alert(alert, index=index)
    
    def generate_savedsearch(self, iocs: List[Dict]) -> str:
        """
        Generate Splunk SPL query for IOC matching
        
        Returns SPL that can be used as a saved search
        """
        ips = [ioc["value"] for ioc in iocs if ioc.get("type") == "ipv4"]
        domains = [ioc["value"] for ioc in iocs if ioc.get("type") == "domain"]
        hashes = [ioc["value"] for ioc in iocs if ioc.get("type") in ["md5", "sha256"]]
        urls = [ioc["value"] for ioc in iocs if ioc.get("type") == "url"]
        
        spl_parts = []
        
        if ips:
            ip_list = " OR ".join([f'"{ip}"' for ip in ips[:100]])  # Limit for SPL
            spl_parts.append(f'(src_ip IN ({ip_list}) OR dest_ip IN ({ip_list}))')
        
        if domains:
            domain_list = " OR ".join([f'"{d}"' for d in domains[:100]])
            spl_parts.append(f'(query IN ({domain_list}) OR url_domain IN ({domain_list}))')
        
        if hashes:
            hash_list = " OR ".join([f'"{h}"' for h in hashes[:100]])
            spl_parts.append(f'(file_hash IN ({hash_list}) OR sha256 IN ({hash_list}) OR md5 IN ({hash_list}))')
        
        if not spl_parts:
            return "| makeresults | eval error=\"No IOCs provided\""
        
        spl = f"""index=* ({" OR ".join(spl_parts)})
| stats count by src_ip, dest_ip, url, file_hash, _time
| sort -_time
| head 1000"""
        
        return spl


if __name__ == "__main__":
    print("=" * 60)
    print("Splunk Integration - Demo")
    print("=" * 60)
    
    splunk = SplunkHEC()
    
    # Demo IOCs
    test_iocs = [
        {"type": "ipv4", "value": "45.33.32.156", "source": "feodotracker", "threat_type": "botnet_c2", "malware": "Emotet", "confidence_score": 85},
        {"type": "domain", "value": "evil-phish.xyz", "source": "openphish", "threat_type": "phishing", "confidence_score": 75},
    ]
    
    print("\nGenerated Splunk SPL Query:")
    print("-" * 40)
    print(splunk.generate_savedsearch(test_iocs))
    
    print("\n" + "-" * 40)
    if not splunk.hec_url:
        print("Note: SPLUNK_HEC_URL not configured")
        print("Set environment variables to enable live integration:")
        print("  export SPLUNK_HEC_URL=https://splunk:8088/services/collector/event")
        print("  export SPLUNK_HEC_TOKEN=your-token")
    else:
        print(f"Splunk HEC configured: {splunk.hec_url}")
