"""
STIX/TAXII Integration - export IOCs in STIX 2.1 format
"""

import json
from datetime import datetime, timezone
from typing import List, Dict
from stix2 import Indicator, Bundle, Malware, Relationship, AttackPattern, Identity


class STIXExporter:
    """Export IOCs to STIX 2.1 format"""
    
    def __init__(self):
        # Create a proper STIX Identity
        self.identity = Identity(
            name="HRTIP Threat Intelligence Platform",
            identity_class="system",
            description="Healthcare & Retail Threat Intelligence Platform"
        )
    
    def ioc_to_stix_pattern(self, ioc: Dict) -> str:
        """Convert IOC to STIX pattern"""
        
        ioc_type = ioc.get("type")
        value = ioc.get("value", "").replace("'", "\\'")
        
        pattern_map = {
            "ipv4": f"[ipv4-addr:value = '{value}']",
            "domain": f"[domain-name:value = '{value}']",
            "url": f"[url:value = '{value}']",
            "md5": f"[file:hashes.MD5 = '{value}']",
            "sha1": f"[file:hashes.'SHA-1' = '{value}']",
            "sha256": f"[file:hashes.'SHA-256' = '{value}']",
            "email": f"[email-addr:value = '{value}']"
        }
        
        return pattern_map.get(ioc_type)
    
    def create_indicator(self, ioc: Dict) -> Indicator:
        """Create a STIX Indicator from an IOC"""
        
        pattern = self.ioc_to_stix_pattern(ioc)
        if not pattern:
            return None
        
        # Map threat types to indicator types
        indicator_types = []
        threat_type = ioc.get("threat_type", "")
        if "botnet" in threat_type or "c2" in threat_type:
            indicator_types.append("malicious-activity")
        if "phishing" in threat_type:
            indicator_types.append("compromised")
        if "malware" in threat_type:
            indicator_types.append("malicious-activity")
        if not indicator_types:
            indicator_types.append("unknown")
        
        # Build labels
        labels = []
        if ioc.get("malware"):
            labels.append(ioc["malware"].lower())
        if ioc.get("threat_type"):
            labels.append(ioc["threat_type"])
        if ioc.get("source"):
            labels.append(f"source:{ioc['source']}")
        
        return Indicator(
            name=f"{ioc.get('type', 'unknown').upper()}: {ioc.get('value', 'unknown')[:50]}",
            description=f"Threat indicator from {ioc.get('source', 'unknown')}. "
                       f"Threat type: {ioc.get('threat_type', 'unknown')}. "
                       f"Malware: {ioc.get('malware', 'unknown')}.",
            pattern=pattern,
            pattern_type="stix",
            indicator_types=indicator_types,
            labels=labels,
            confidence=ioc.get("confidence_score", 50),
            valid_from=datetime.now(timezone.utc),
            created_by_ref=self.identity.id
        )
    
    def create_malware(self, name: str, malware_types: List[str] = None) -> Malware:
        """Create a STIX Malware object"""
        
        return Malware(
            name=name,
            is_family=True,
            malware_types=malware_types or ["unknown"],
            created_by_ref=self.identity.id
        )
    
    def export_iocs(self, iocs: List[Dict]) -> Bundle:
        """Export IOCs to a STIX Bundle"""
        
        objects = [self.identity]
        malware_cache = {}
        
        for ioc in iocs:
            indicator = self.create_indicator(ioc)
            if indicator:
                objects.append(indicator)
                
                # Create malware object and relationship if applicable
                malware_name = ioc.get("malware")
                if malware_name and malware_name not in malware_cache:
                    malware_types = ["bot"] if "botnet" in ioc.get("threat_type", "") else ["unknown"]
                    malware = self.create_malware(malware_name, malware_types)
                    malware_cache[malware_name] = malware
                    objects.append(malware)
                
                # Create relationship
                if malware_name and malware_name in malware_cache:
                    relationship = Relationship(
                        relationship_type="indicates",
                        source_ref=indicator.id,
                        target_ref=malware_cache[malware_name].id
                    )
                    objects.append(relationship)
        
        return Bundle(objects=objects)
    
    def export_to_json(self, iocs: List[Dict], pretty: bool = True) -> str:
        """Export IOCs to STIX JSON string"""
        
        bundle = self.export_iocs(iocs)
        return bundle.serialize(pretty=pretty)
    
    def export_to_file(self, iocs: List[Dict], filename: str):
        """Export IOCs to STIX JSON file"""
        
        with open(filename, "w") as f:
            f.write(self.export_to_json(iocs))
        
        return filename
    
    def create_attack_pattern(self, technique_id: str, technique_name: str) -> AttackPattern:
        """Create STIX Attack Pattern from MITRE technique"""
        
        return AttackPattern(
            name=technique_name,
            external_references=[{
                "source_name": "mitre-attack",
                "external_id": technique_id,
                "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
            }],
            created_by_ref=self.identity.id
        )


if __name__ == "__main__":
    print("=" * 60)
    print("STIX/TAXII Exporter - Demo")
    print("=" * 60)
    
    exporter = STIXExporter()
    
    test_iocs = [
        {
            "type": "ipv4", 
            "value": "45.33.32.156", 
            "source": "feodotracker", 
            "threat_type": "botnet_c2", 
            "malware": "Emotet", 
            "confidence_score": 85
        },
        {
            "type": "domain", 
            "value": "evil-phish.xyz", 
            "source": "openphish", 
            "threat_type": "phishing", 
            "confidence_score": 75
        },
        {
            "type": "sha256", 
            "value": "a" * 64, 
            "source": "malwarebazaar", 
            "threat_type": "malware", 
            "malware": "Mirai", 
            "confidence_score": 90
        },
    ]
    
    print("\nGenerated STIX 2.1 Bundle:")
    print("-" * 40)
    stix_json = exporter.export_to_json(test_iocs)
    parsed = json.loads(stix_json)
    print(f"Bundle ID: {parsed['id']}")
    print(f"Objects: {len(parsed['objects'])}")
    for obj in parsed['objects']:
        print(f"  - {obj['type']}: {obj.get('name', obj.get('id', 'unknown'))[:60]}")
    
    # Save to file
    exporter.export_to_file(test_iocs, "data/stix_export.json")
    print(f"\nExported to: data/stix_export.json")
