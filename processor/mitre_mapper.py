"""
MITRE ATT&CK Mapper - maps IOCs and threat data to ATT&CK techniques
"""

from typing import Dict, List, Optional


# Mapping of malware families to ATT&CK techniques
MALWARE_TO_ATTACK = {
    "emotet": {
        "techniques": ["T1566.001", "T1059.005", "T1547.001", "T1055", "T1573"],
        "tactics": ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Command and Control"],
        "description": "Banking trojan turned malware loader"
    },
    "cobalt strike": {
        "techniques": ["T1059.001", "T1055", "T1071.001", "T1573.002", "T1105"],
        "tactics": ["Execution", "Defense Evasion", "Command and Control", "Lateral Movement"],
        "description": "Commercial adversary simulation tool often abused by threat actors"
    },
    "cobaltstrike": {
        "techniques": ["T1059.001", "T1055", "T1071.001", "T1573.002", "T1105"],
        "tactics": ["Execution", "Defense Evasion", "Command and Control", "Lateral Movement"],
        "description": "Commercial adversary simulation tool often abused by threat actors"
    },
    "qakbot": {
        "techniques": ["T1566.001", "T1059.001", "T1547.001", "T1055", "T1071.001"],
        "tactics": ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Command and Control"],
        "description": "Banking trojan and malware distributor"
    },
    "mirai": {
        "techniques": ["T1110.001", "T1059.004", "T1499.002", "T1571"],
        "tactics": ["Credential Access", "Execution", "Impact", "Command and Control"],
        "description": "IoT botnet targeting embedded devices"
    },
    "smoke loader": {
        "techniques": ["T1566.001", "T1059.001", "T1055", "T1071.001", "T1105"],
        "tactics": ["Initial Access", "Execution", "Defense Evasion", "Command and Control"],
        "description": "Modular malware loader"
    },
    "smokeloader": {
        "techniques": ["T1566.001", "T1059.001", "T1055", "T1071.001", "T1105"],
        "tactics": ["Initial Access", "Execution", "Defense Evasion", "Command and Control"],
        "description": "Modular malware loader"
    },
    "raccoon": {
        "techniques": ["T1555", "T1539", "T1552.001", "T1041"],
        "tactics": ["Credential Access", "Collection", "Exfiltration"],
        "description": "Information stealer malware"
    },
    "redline": {
        "techniques": ["T1555", "T1539", "T1552.001", "T1041", "T1113"],
        "tactics": ["Credential Access", "Collection", "Exfiltration"],
        "description": "Information stealer targeting browsers and crypto wallets"
    },
    "asyncrat": {
        "techniques": ["T1059.001", "T1547.001", "T1055", "T1113", "T1125"],
        "tactics": ["Execution", "Persistence", "Defense Evasion", "Collection"],
        "description": "Open-source remote access trojan"
    },
    "stealc": {
        "techniques": ["T1555", "T1539", "T1552.001", "T1041"],
        "tactics": ["Credential Access", "Collection", "Exfiltration"],
        "description": "Information stealer malware"
    },
    "meterpreter": {
        "techniques": ["T1059", "T1055", "T1071", "T1573", "T1105"],
        "tactics": ["Execution", "Defense Evasion", "Command and Control"],
        "description": "Metasploit payload for post-exploitation"
    },
}

# Mapping of threat types to ATT&CK techniques
THREAT_TYPE_TO_ATTACK = {
    "botnet_c2": {
        "techniques": ["T1071.001", "T1573", "T1571", "T1095"],
        "tactics": ["Command and Control"],
        "description": "Botnet command and control infrastructure"
    },
    "phishing": {
        "techniques": ["T1566.001", "T1566.002", "T1598"],
        "tactics": ["Initial Access", "Reconnaissance"],
        "description": "Phishing attack infrastructure"
    },
    "malware_download": {
        "techniques": ["T1105", "T1204.002", "T1059"],
        "tactics": ["Command and Control", "Execution"],
        "description": "Malware distribution infrastructure"
    },
    "ransomware": {
        "techniques": ["T1486", "T1490", "T1489", "T1106"],
        "tactics": ["Impact", "Defense Evasion"],
        "description": "Ransomware attack infrastructure"
    },
}

# ATT&CK technique details
TECHNIQUE_DETAILS = {
    "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access"},
    "T1566.002": {"name": "Phishing: Spearphishing Link", "tactic": "Initial Access"},
    "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution"},
    "T1059.004": {"name": "Command and Scripting Interpreter: Unix Shell", "tactic": "Execution"},
    "T1059.005": {"name": "Command and Scripting Interpreter: Visual Basic", "tactic": "Execution"},
    "T1547.001": {"name": "Boot or Logon Autostart Execution: Registry Run Keys", "tactic": "Persistence"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
    "T1573": {"name": "Encrypted Channel", "tactic": "Command and Control"},
    "T1573.002": {"name": "Encrypted Channel: Asymmetric Cryptography", "tactic": "Command and Control"},
    "T1571": {"name": "Non-Standard Port", "tactic": "Command and Control"},
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": "Command and Control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1110.001": {"name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    "T1499.002": {"name": "Endpoint Denial of Service: Service Exhaustion Flood", "tactic": "Impact"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "Credential Access"},
    "T1539": {"name": "Steal Web Session Cookie", "tactic": "Credential Access"},
    "T1552.001": {"name": "Unsecured Credentials: Credentials In Files", "tactic": "Credential Access"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1113": {"name": "Screen Capture", "tactic": "Collection"},
    "T1125": {"name": "Video Capture", "tactic": "Collection"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1489": {"name": "Service Stop", "tactic": "Impact"},
    "T1204.002": {"name": "User Execution: Malicious File", "tactic": "Execution"},
    "T1598": {"name": "Phishing for Information", "tactic": "Reconnaissance"},
}


class MITREMapper:
    def __init__(self):
        self.malware_map = MALWARE_TO_ATTACK
        self.threat_type_map = THREAT_TYPE_TO_ATTACK
        self.technique_details = TECHNIQUE_DETAILS
    
    def map_ioc(self, ioc: Dict) -> Dict:
        """Map an IOC to MITRE ATT&CK techniques"""
        
        result = ioc.copy()
        result["mitre_attack"] = {
            "techniques": [],
            "tactics": [],
            "mappings": []
        }
        
        # Check malware family
        malware = ioc.get("malware", "")
        if malware:
            malware_lower = malware.lower().replace(" ", "").replace("_", "")
            for mal_name, mal_data in self.malware_map.items():
                if mal_name.replace(" ", "") in malware_lower or malware_lower in mal_name.replace(" ", ""):
                    result["mitre_attack"]["techniques"].extend(mal_data["techniques"])
                    result["mitre_attack"]["tactics"].extend(mal_data["tactics"])
                    result["mitre_attack"]["mappings"].append({
                        "source": "malware_family",
                        "value": malware,
                        "matched": mal_name,
                        "description": mal_data["description"]
                    })
                    break
        
        # Check threat type
        threat_type = ioc.get("threat_type", "")
        if threat_type and threat_type in self.threat_type_map:
            tt_data = self.threat_type_map[threat_type]
            result["mitre_attack"]["techniques"].extend(tt_data["techniques"])
            result["mitre_attack"]["tactics"].extend(tt_data["tactics"])
            result["mitre_attack"]["mappings"].append({
                "source": "threat_type",
                "value": threat_type,
                "description": tt_data["description"]
            })
        
        # Deduplicate
        result["mitre_attack"]["techniques"] = list(set(result["mitre_attack"]["techniques"]))
        result["mitre_attack"]["tactics"] = list(set(result["mitre_attack"]["tactics"]))
        
        # Add technique details
        result["mitre_attack"]["technique_details"] = []
        for tech_id in result["mitre_attack"]["techniques"]:
            if tech_id in self.technique_details:
                detail = self.technique_details[tech_id].copy()
                detail["id"] = tech_id
                detail["url"] = f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
                result["mitre_attack"]["technique_details"].append(detail)
        
        return result
    
    def map_multiple(self, iocs: List[Dict]) -> List[Dict]:
        """Map multiple IOCs to ATT&CK"""
        return [self.map_ioc(ioc) for ioc in iocs]
    
    def generate_attack_summary(self, mapped_iocs: List[Dict]) -> Dict:
        """Generate a summary of ATT&CK coverage"""
        
        all_techniques = []
        all_tactics = []
        malware_families = []
        
        for ioc in mapped_iocs:
            attack_data = ioc.get("mitre_attack", {})
            all_techniques.extend(attack_data.get("techniques", []))
            all_tactics.extend(attack_data.get("tactics", []))
            
            for mapping in attack_data.get("mappings", []):
                if mapping.get("source") == "malware_family":
                    malware_families.append(mapping.get("matched"))
        
        # Count occurrences
        from collections import Counter
        technique_counts = Counter(all_techniques)
        tactic_counts = Counter(all_tactics)
        malware_counts = Counter(malware_families)
        
        return {
            "total_iocs_mapped": len([i for i in mapped_iocs if i.get("mitre_attack", {}).get("techniques")]),
            "unique_techniques": len(set(all_techniques)),
            "unique_tactics": len(set(all_tactics)),
            "top_techniques": technique_counts.most_common(10),
            "top_tactics": tactic_counts.most_common(10),
            "malware_families": malware_counts.most_common(10)
        }


if __name__ == "__main__":
    mapper = MITREMapper()
    
    # Test with sample IOCs
    test_iocs = [
        {"type": "ip", "value": "162.243.103.246", "malware": "Emotet", "threat_type": "botnet_c2"},
        {"type": "sha256", "value": "abc123", "malware": "CobaltStrike", "threat_type": "malware"},
        {"type": "url", "value": "http://evil.com", "threat_type": "phishing"},
        {"type": "sha256", "value": "def456", "malware": "Mirai", "threat_type": "botnet_c2"},
        {"type": "ip", "value": "1.2.3.4", "malware": "Smoke Loader", "threat_type": "malware_download"},
    ]
    
    print("=" * 60)
    print("MITRE ATT&CK Mapper - Testing")
    print("=" * 60)
    
    mapped = mapper.map_multiple(test_iocs)
    
    for ioc in mapped:
        attack = ioc.get("mitre_attack", {})
        if attack.get("techniques"):
            print(f"\n[{ioc['type']}] {ioc.get('malware', 'Unknown')}")
            print(f"  Techniques: {attack['techniques']}")
            print(f"  Tactics: {attack['tactics']}")
            for detail in attack.get("technique_details", [])[:3]:
                print(f"    - {detail['id']}: {detail['name']}")
    
    print("\n" + "=" * 60)
    print("ATT&CK Summary")
    print("=" * 60)
    
    summary = mapper.generate_attack_summary(mapped)
    print(f"IOCs mapped: {summary['total_iocs_mapped']}/{len(test_iocs)}")
    print(f"Unique techniques: {summary['unique_techniques']}")
    print(f"Unique tactics: {summary['unique_tactics']}")
    print(f"Top techniques: {summary['top_techniques'][:5]}")
    print(f"Malware families: {summary['malware_families']}")
