"""
Microsoft Sentinel Integration - push IOCs to Sentinel via Log Analytics API
"""

import requests
import json
import hashlib
import hmac
import base64
from datetime import datetime, timezone
from typing import List, Dict
import os


class SentinelConnector:
    """Microsoft Sentinel Log Analytics integration"""
    
    def __init__(self, workspace_id: str = None, shared_key: str = None):
        """
        Initialize Sentinel connection
        
        Args:
            workspace_id: Log Analytics Workspace ID
            shared_key: Log Analytics Primary/Secondary Key
        """
        self.workspace_id = workspace_id or os.getenv("SENTINEL_WORKSPACE_ID")
        self.shared_key = shared_key or os.getenv("SENTINEL_SHARED_KEY")
        self.log_type = "HRTIP_ThreatIntel"
    
    def _build_signature(self, date: str, content_length: int, method: str, content_type: str, resource: str) -> str:
        """Build the authorization signature for Log Analytics API"""
        
        x_headers = f"x-ms-date:{date}"
        string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
        bytes_to_hash = string_to_hash.encode('utf-8')
        decoded_key = base64.b64decode(self.shared_key)
        encoded_hash = base64.b64encode(
            hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
        ).decode('utf-8')
        
        return f"SharedKey {self.workspace_id}:{encoded_hash}"
    
    def _send_data(self, data: List[Dict], log_type: str = None) -> Dict:
        """Send data to Log Analytics"""
        
        if not self.workspace_id or not self.shared_key:
            return {"status": "error", "message": "Sentinel not configured"}
        
        log_type = log_type or self.log_type
        body = json.dumps(data)
        content_length = len(body)
        
        rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        
        signature = self._build_signature(
            rfc1123date, content_length, "POST", "application/json", "/api/logs"
        )
        
        uri = f"https://{self.workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": signature,
            "Log-Type": log_type,
            "x-ms-date": rfc1123date,
            "time-generated-field": "TimeGenerated"
        }
        
        try:
            response = requests.post(uri, data=body, headers=headers, timeout=30)
            
            if response.status_code in [200, 202]:
                return {"status": "success", "records_sent": len(data)}
            else:
                return {"status": "error", "code": response.status_code, "message": response.text}
                
        except requests.RequestException as e:
            return {"status": "error", "message": str(e)}
    
    def send_iocs(self, iocs: List[Dict]) -> Dict:
        """
        Send IOCs to Sentinel as custom logs
        
        These will appear in the HRTIP_ThreatIntel_CL table
        """
        records = []
        
        for ioc in iocs:
            record = {
                "TimeGenerated": datetime.now(timezone.utc).isoformat(),
                "IOCType": ioc.get("type"),
                "IOCValue": ioc.get("value"),
                "Source": ioc.get("source"),
                "ThreatType": ioc.get("threat_type"),
                "MalwareFamily": ioc.get("malware"),
                "ConfidenceScore": ioc.get("confidence_score"),
                "MITRETechniques": ",".join(ioc.get("mitre_attack", {}).get("techniques", [])),
                "MITRETactics": ",".join(ioc.get("mitre_attack", {}).get("tactics", [])),
                "Tags": ",".join(ioc.get("tags", [])) if ioc.get("tags") else "",
                "FirstSeen": ioc.get("first_seen"),
                "CollectedAt": ioc.get("collected_at")
            }
            records.append(record)
        
        return self._send_data(records, "HRTIP_IOC")
    
    def send_alert(self, alert: Dict) -> Dict:
        """Send an alert to Sentinel"""
        
        record = {
            "TimeGenerated": datetime.now(timezone.utc).isoformat(),
            "AlertTitle": alert.get("title"),
            "Severity": alert.get("severity", "Medium"),
            "Description": alert.get("description"),
            "IOCCount": len(alert.get("iocs", [])),
            "IOCs": json.dumps(alert.get("iocs", [])),
            "MITRETechniques": ",".join(alert.get("mitre_techniques", [])),
            "RecommendedActions": json.dumps(alert.get("recommended_actions", [])),
            "Source": "HRTIP"
        }
        
        return self._send_data([record], "HRTIP_Alert")
    
    def generate_kql_query(self, iocs: List[Dict]) -> str:
        """
        Generate KQL query for IOC hunting in Sentinel
        
        Returns KQL that can be used in Sentinel workbooks or hunting queries
        """
        ips = [ioc["value"] for ioc in iocs if ioc.get("type") == "ipv4"]
        domains = [ioc["value"] for ioc in iocs if ioc.get("type") == "domain"]
        hashes = [ioc["value"] for ioc in iocs if ioc.get("type") in ["md5", "sha256"]]
        
        kql_parts = []
        
        # Network connections - IPs
        if ips:
            ip_list = '", "'.join(ips[:50])
            kql_parts.append(f'''
// Hunt for malicious IPs in network logs
CommonSecurityLog
| where DestinationIP in ("{ip_list}") or SourceIP in ("{ip_list}")
| project TimeGenerated, DeviceVendor, SourceIP, DestinationIP, DestinationPort, Activity
| take 100''')
        
        # DNS queries - domains
        if domains:
            domain_list = '", "'.join(domains[:50])
            kql_parts.append(f'''
// Hunt for malicious domains in DNS logs
DnsEvents
| where Name has_any ("{domain_list}")
| project TimeGenerated, Computer, Name, QueryType, IPAddresses
| take 100''')
        
        # File hashes
        if hashes:
            hash_list = '", "'.join(hashes[:50])
            kql_parts.append(f'''
// Hunt for malicious file hashes
DeviceFileEvents
| where SHA256 in ("{hash_list}") or MD5 in ("{hash_list}")
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, MD5
| take 100''')
        
        # Combine queries
        if kql_parts:
            return "\n\n".join(kql_parts)
        else:
            return "// No IOCs provided for query generation"
    
    def generate_analytics_rule(self, rule_name: str, iocs: List[Dict]) -> Dict:
        """
        Generate Sentinel Analytics Rule definition
        
        Returns a dict that can be used to create a scheduled analytics rule
        """
        ips = [ioc["value"] for ioc in iocs if ioc.get("type") == "ipv4"]
        domains = [ioc["value"] for ioc in iocs if ioc.get("type") == "domain"]
        
        # Build dynamic KQL
        conditions = []
        if ips:
            ip_list = '", "'.join(ips[:100])
            conditions.append(f'DestinationIP in ("{ip_list}")')
        if domains:
            domain_list = '", "'.join(domains[:100])
            conditions.append(f'Name has_any ("{domain_list}")')
        
        query = f"""
let ThreatIOCs = dynamic([{','.join([f'"{ioc["value"]}"' for ioc in iocs[:100]])}]);
union CommonSecurityLog, DnsEvents
| where DestinationIP in (ThreatIOCs) or SourceIP in (ThreatIOCs) or Name has_any (ThreatIOCs)
| summarize Count=count() by bin(TimeGenerated, 1h), SourceIP, DestinationIP, Name
| where Count > 0
"""
        
        return {
            "displayName": rule_name,
            "description": f"HRTIP generated rule - detects {len(iocs)} known threat indicators",
            "severity": "High",
            "enabled": True,
            "query": query,
            "queryFrequency": "PT1H",
            "queryPeriod": "PT1H",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "tactics": ["CommandAndControl", "Exfiltration"],
            "techniques": list(set(
                tech for ioc in iocs 
                for tech in ioc.get("mitre_attack", {}).get("techniques", [])
            ))[:10]
        }


if __name__ == "__main__":
    print("=" * 60)
    print("Microsoft Sentinel Integration - Demo")
    print("=" * 60)
    
    sentinel = SentinelConnector()
    
    # Demo IOCs
    test_iocs = [
        {"type": "ipv4", "value": "45.33.32.156", "source": "feodotracker", "threat_type": "botnet_c2", "malware": "Emotet"},
        {"type": "domain", "value": "evil-phish.xyz", "source": "openphish", "threat_type": "phishing"},
        {"type": "sha256", "value": "a" * 64, "source": "malwarebazaar", "threat_type": "malware", "malware": "Mirai"},
    ]
    
    print("\nGenerated KQL Hunting Query:")
    print("-" * 40)
    print(sentinel.generate_kql_query(test_iocs))
    
    print("\n" + "-" * 40)
    print("Generated Analytics Rule:")
    print("-" * 40)
    rule = sentinel.generate_analytics_rule("HRTIP Threat Detection", test_iocs)
    print(f"Name: {rule['displayName']}")
    print(f"Severity: {rule['severity']}")
    print(f"Tactics: {rule['tactics']}")
    
    print("\n" + "-" * 40)
    if not sentinel.workspace_id:
        print("Note: SENTINEL_WORKSPACE_ID not configured")
        print("Set environment variables to enable live integration:")
        print("  export SENTINEL_WORKSPACE_ID=your-workspace-id")
        print("  export SENTINEL_SHARED_KEY=your-shared-key")
