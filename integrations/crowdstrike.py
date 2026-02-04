"""
CrowdStrike Falcon Integration - push IOCs to custom IOC management
"""

import requests
import json
from datetime import datetime, timezone, timedelta
from typing import List, Dict
import os


class CrowdStrikeIOC:
    """CrowdStrike Falcon IOC Management integration"""
    
    def __init__(self, client_id: str = None, client_secret: str = None, base_url: str = None):
        """
        Initialize CrowdStrike API connection
        
        Args:
            client_id: API Client ID
            client_secret: API Client Secret
            base_url: CrowdStrike API base URL (default: US-1)
        """
        self.client_id = client_id or os.getenv("CS_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("CS_CLIENT_SECRET")
        self.base_url = base_url or os.getenv("CS_BASE_URL", "https://api.crowdstrike.com")
        self.access_token = None
        self.token_expiry = None
    
    def _authenticate(self) -> bool:
        """Authenticate and get access token"""
        
        if not self.client_id or not self.client_secret:
            return False
        
        # Check if token is still valid
        if self.access_token and self.token_expiry and datetime.now() < self.token_expiry:
            return True
        
        url = f"{self.base_url}/oauth2/token"
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        
        try:
            response = requests.post(url, data=data, timeout=30)
            if response.status_code == 201:
                token_data = response.json()
                self.access_token = token_data["access_token"]
                expires_in = token_data.get("expires_in", 1800)
                self.token_expiry = datetime.now() + timedelta(seconds=expires_in - 60)
                return True
            return False
        except Exception:
            return False
    
    def _api_request(self, method: str, endpoint: str, data: Dict = None) -> Dict:
        """Make authenticated API request"""
        
        if not self._authenticate():
            return {"status": "error", "message": "Authentication failed or not configured"}
        
        url = f"{self.base_url}{endpoint}"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=30)
            elif method == "POST":
                response = requests.post(url, headers=headers, json=data, timeout=30)
            elif method == "DELETE":
                response = requests.delete(url, headers=headers, json=data, timeout=30)
            else:
                return {"status": "error", "message": f"Unsupported method: {method}"}
            
            if response.status_code in [200, 201]:
                return {"status": "success", "data": response.json()}
            else:
                return {"status": "error", "code": response.status_code, "message": response.text}
                
        except requests.RequestException as e:
            return {"status": "error", "message": str(e)}
    
    def upload_iocs(self, iocs: List[Dict], action: str = "detect") -> Dict:
        """
        Upload IOCs to CrowdStrike Custom IOC Management
        
        Args:
            iocs: List of IOC dictionaries
            action: Action to take (detect, prevent, no_action)
        """
        indicators = []
        
        for ioc in iocs:
            ioc_type = ioc.get("type")
            value = ioc.get("value")
            
            # Map HRTIP types to CrowdStrike types
            cs_type_map = {
                "ipv4": "ipv4",
                "domain": "domain",
                "md5": "md5",
                "sha256": "sha256"
            }
            
            cs_type = cs_type_map.get(ioc_type)
            if not cs_type:
                continue
            
            # Calculate expiration (default 90 days)
            expiration = (datetime.now(timezone.utc) + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
            
            indicator = {
                "type": cs_type,
                "value": value,
                "action": action,
                "severity": self._map_severity(ioc.get("confidence_score", 50)),
                "description": f"HRTIP: {ioc.get('threat_type', 'unknown')} - {ioc.get('malware', 'unknown')}",
                "source": "HRTIP",
                "platforms": ["windows", "mac", "linux"],
                "expiration": expiration,
                "tags": [ioc.get("source", "hrtip"), ioc.get("threat_type", "threat")]
            }
            
            indicators.append(indicator)
        
        if not indicators:
            return {"status": "error", "message": "No valid IOCs to upload"}
        
        return self._api_request("POST", "/iocs/entities/indicators/v1", {"indicators": indicators})
    
    def _map_severity(self, confidence_score: int) -> str:
        """Map confidence score to CrowdStrike severity"""
        if confidence_score >= 80:
            return "critical"
        elif confidence_score >= 60:
            return "high"
        elif confidence_score >= 40:
            return "medium"
        else:
            return "low"
    
    def search_iocs(self, ioc_type: str = None, value: str = None) -> Dict:
        """Search for existing IOCs"""
        
        filter_parts = []
        if ioc_type:
            filter_parts.append(f"type:'{ioc_type}'")
        if value:
            filter_parts.append(f"value:'{value}'")
        
        filter_str = "+".join(filter_parts) if filter_parts else ""
        endpoint = f"/iocs/queries/indicators/v1?filter={filter_str}" if filter_str else "/iocs/queries/indicators/v1"
        
        return self._api_request("GET", endpoint)
    
    def delete_iocs(self, ioc_ids: List[str]) -> Dict:
        """Delete IOCs by ID"""
        
        return self._api_request("DELETE", "/iocs/entities/indicators/v1", {"ids": ioc_ids})
    
    def generate_falcon_query(self, iocs: List[Dict]) -> str:
        """
        Generate Falcon Query Language (FQL) for hunting
        
        Returns FQL that can be used in Falcon UI or API
        """
        ips = [ioc["value"] for ioc in iocs if ioc.get("type") == "ipv4"]
        domains = [ioc["value"] for ioc in iocs if ioc.get("type") == "domain"]
        hashes = [ioc["value"] for ioc in iocs if ioc.get("type") in ["md5", "sha256"]]
        
        queries = []
        
        if ips:
            ip_list = ",".join(f"'{ip}'" for ip in ips[:50])
            queries.append(f"RemoteAddressIP4:[{ip_list}]")
        
        if domains:
            domain_list = ",".join(f"'{d}'" for d in domains[:50])
            queries.append(f"DomainName:[{domain_list}]")
        
        if hashes:
            hash_list = ",".join(f"'{h}'" for h in hashes[:50])
            queries.append(f"SHA256HashData:[{hash_list}] OR MD5HashData:[{hash_list}]")
        
        return " OR ".join(queries) if queries else "// No IOCs for query"


if __name__ == "__main__":
    print("=" * 60)
    print("CrowdStrike Falcon Integration - Demo")
    print("=" * 60)
    
    cs = CrowdStrikeIOC()
    
    # Demo IOCs
    test_iocs = [
        {"type": "ipv4", "value": "45.33.32.156", "source": "feodotracker", "threat_type": "botnet_c2", "malware": "Emotet", "confidence_score": 85},
        {"type": "domain", "value": "evil-phish.xyz", "source": "openphish", "threat_type": "phishing", "confidence_score": 75},
        {"type": "sha256", "value": "a" * 64, "source": "malwarebazaar", "threat_type": "malware", "malware": "Mirai", "confidence_score": 90},
    ]
    
    print("\nGenerated Falcon Query Language (FQL):")
    print("-" * 40)
    print(cs.generate_falcon_query(test_iocs))
    
    print("\n" + "-" * 40)
    if not cs.client_id:
        print("Note: CS_CLIENT_ID not configured")
        print("Set environment variables to enable live integration:")
        print("  export CS_CLIENT_ID=your-client-id")
        print("  export CS_CLIENT_SECRET=your-client-secret")
        print("  export CS_BASE_URL=https://api.crowdstrike.com")
