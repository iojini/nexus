"""
Threat Actor Clustering - groups IOCs into likely campaigns using ML
Uses unsupervised learning to identify related threat activity
"""

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Optional
import re


class ThreatClusterer:
    """Clusters IOCs into potential threat actor campaigns"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.vectorizer = TfidfVectorizer(max_features=100)
    
    def extract_features(self, iocs: List[Dict]) -> np.ndarray:
        """Extract numerical features from IOCs for clustering"""
        
        features = []
        
        for ioc in iocs:
            feature_vec = []
            
            # 1. IOC type encoding
            ioc_type = ioc.get("type", "unknown")
            type_encoding = {
                "ipv4": [1, 0, 0, 0, 0],
                "domain": [0, 1, 0, 0, 0],
                "url": [0, 0, 1, 0, 0],
                "sha256": [0, 0, 0, 1, 0],
                "md5": [0, 0, 0, 0, 1],
            }
            feature_vec.extend(type_encoding.get(ioc_type, [0, 0, 0, 0, 0]))
            
            # 2. Source encoding
            source = ioc.get("source", "unknown")
            source_encoding = {
                "feodotracker": [1, 0, 0, 0, 0, 0],
                "urlhaus": [0, 1, 0, 0, 0, 0],
                "threatfox": [0, 0, 1, 0, 0, 0],
                "malwarebazaar": [0, 0, 0, 1, 0, 0],
                "openphish": [0, 0, 0, 0, 1, 0],
                "alienvault_otx": [0, 0, 0, 0, 0, 1],
            }
            feature_vec.extend(source_encoding.get(source, [0, 0, 0, 0, 0, 0]))
            
            # 3. Threat type encoding
            threat_type = ioc.get("threat_type", "unknown")
            threat_encoding = {
                "botnet_c2": [1, 0, 0, 0],
                "malware": [0, 1, 0, 0],
                "malware_download": [0, 1, 0, 0],
                "phishing": [0, 0, 1, 0],
                "ransomware": [0, 0, 0, 1],
            }
            feature_vec.extend(threat_encoding.get(threat_type, [0, 0, 0, 0]))
            
            # 4. IP-based features (if applicable)
            value = str(ioc.get("value", ""))
            if ioc_type == "ipv4":
                octets = value.split(".")
                if len(octets) == 4:
                    # First two octets as features (ASN approximation)
                    feature_vec.extend([int(octets[0])/255, int(octets[1])/255])
                else:
                    feature_vec.extend([0, 0])
            else:
                feature_vec.extend([0, 0])
            
            # 5. Domain-based features
            if ioc_type == "domain":
                # Domain length (normalized)
                feature_vec.append(min(len(value), 50) / 50)
                # Number of subdomains
                feature_vec.append(min(value.count('.'), 5) / 5)
                # Contains numbers
                feature_vec.append(1 if any(c.isdigit() for c in value) else 0)
            else:
                feature_vec.extend([0, 0, 0])
            
            # 6. Port features (if available)
            port = ioc.get("port", 0)
            if port:
                # Common malicious ports
                common_ports = [80, 443, 8080, 8443, 4444, 1337, 9999]
                feature_vec.append(1 if port in common_ports else 0)
                feature_vec.append(min(port, 65535) / 65535)
            else:
                feature_vec.extend([0, 0])
            
            # 7. Confidence score (if available)
            confidence = ioc.get("confidence_score", 50)
            feature_vec.append(confidence / 100)
            
            # 8. Malware family presence
            malware = ioc.get("malware", "")
            feature_vec.append(1 if malware else 0)
            
            features.append(feature_vec)
        
        return np.array(features)
    
    def cluster(self, iocs: List[Dict], eps: float = 0.5, min_samples: int = 2) -> List[Dict]:
        """
        Cluster IOCs into potential campaigns
        
        Args:
            iocs: List of IOC dictionaries
            eps: DBSCAN epsilon (max distance between samples)
            min_samples: Minimum samples to form a cluster
        
        Returns:
            IOCs with cluster labels added
        """
        
        if len(iocs) < min_samples:
            # Not enough IOCs to cluster
            for ioc in iocs:
                ioc["cluster_id"] = -1
                ioc["cluster_info"] = {"status": "insufficient_data"}
            return iocs
        
        # Extract features
        features = self.extract_features(iocs)
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features)
        
        # Run DBSCAN clustering
        clustering = DBSCAN(eps=eps, min_samples=min_samples, metric='euclidean')
        labels = clustering.fit_predict(features_scaled)
        
        # Add cluster labels to IOCs
        for i, ioc in enumerate(iocs):
            ioc["cluster_id"] = int(labels[i])
        
        return iocs
    
    def analyze_clusters(self, clustered_iocs: List[Dict]) -> Dict:
        """Analyze the identified clusters"""
        
        clusters = defaultdict(list)
        for ioc in clustered_iocs:
            cluster_id = ioc.get("cluster_id", -1)
            clusters[cluster_id].append(ioc)
        
        analysis = {
            "total_iocs": len(clustered_iocs),
            "num_clusters": len([c for c in clusters.keys() if c != -1]),
            "noise_points": len(clusters.get(-1, [])),
            "clusters": []
        }
        
        for cluster_id, members in clusters.items():
            if cluster_id == -1:
                continue  # Skip noise
            
            # Analyze cluster characteristics
            sources = set(m.get("source") for m in members)
            threat_types = set(m.get("threat_type") for m in members if m.get("threat_type"))
            malware_families = set(m.get("malware") for m in members if m.get("malware"))
            ioc_types = set(m.get("type") for m in members)
            
            cluster_info = {
                "cluster_id": cluster_id,
                "size": len(members),
                "sources": list(sources),
                "threat_types": list(threat_types),
                "malware_families": list(malware_families),
                "ioc_types": list(ioc_types),
                "sample_iocs": [m.get("value", "")[:50] for m in members[:5]],
                "potential_campaign": self._identify_campaign(members)
            }
            
            analysis["clusters"].append(cluster_info)
        
        # Sort by cluster size
        analysis["clusters"].sort(key=lambda x: x["size"], reverse=True)
        
        return analysis
    
    def _identify_campaign(self, members: List[Dict]) -> str:
        """Try to identify the campaign type based on cluster members"""
        
        malware_families = [m.get("malware", "").lower() for m in members if m.get("malware")]
        threat_types = [m.get("threat_type", "") for m in members if m.get("threat_type")]
        
        # Check for known malware families
        known_campaigns = {
            "emotet": "Emotet Botnet Campaign",
            "qakbot": "QakBot Distribution Campaign",
            "cobalt": "Cobalt Strike Infrastructure",
            "cobaltstrike": "Cobalt Strike Infrastructure",
            "mirai": "Mirai Botnet Activity",
            "dridex": "Dridex Banking Trojan Campaign",
            "trickbot": "TrickBot Campaign",
            "asyncrat": "AsyncRAT Distribution",
            "redline": "RedLine Stealer Campaign",
            "raccoon": "Raccoon Stealer Campaign",
        }
        
        for family in malware_families:
            for key, campaign in known_campaigns.items():
                if key in family:
                    return campaign
        
        # Infer from threat types
        if "botnet_c2" in threat_types:
            return "Botnet C2 Infrastructure"
        elif "phishing" in threat_types:
            return "Phishing Campaign"
        elif "ransomware" in threat_types:
            return "Ransomware Campaign"
        
        return "Unknown Campaign"


if __name__ == "__main__":
    print("=" * 60)
    print("Threat Actor Clustering - Testing")
    print("=" * 60)
    
    # Test with sample IOCs
    test_iocs = [
        # Emotet cluster
        {"type": "ipv4", "value": "162.243.103.246", "source": "feodotracker", "threat_type": "botnet_c2", "malware": "Emotet", "port": 8080},
        {"type": "ipv4", "value": "167.86.75.145", "source": "feodotracker", "threat_type": "botnet_c2", "malware": "Emotet", "port": 443},
        {"type": "ipv4", "value": "185.148.168.220", "source": "threatfox", "threat_type": "botnet_c2", "malware": "Emotet", "port": 8080},
        
        # Phishing cluster
        {"type": "url", "value": "http://fake-bank.com/login", "source": "openphish", "threat_type": "phishing"},
        {"type": "url", "value": "http://secure-paypal.xyz/verify", "source": "openphish", "threat_type": "phishing"},
        {"type": "domain", "value": "amazon-security.tk", "source": "openphish", "threat_type": "phishing"},
        
        # Malware distribution
        {"type": "sha256", "value": "abc123", "source": "malwarebazaar", "threat_type": "malware", "malware": "Mirai"},
        {"type": "sha256", "value": "def456", "source": "malwarebazaar", "threat_type": "malware", "malware": "Mirai"},
        
        # Noise (unrelated)
        {"type": "domain", "value": "random-site.com", "source": "alienvault_otx", "threat_type": "malware"},
    ]
    
    clusterer = ThreatClusterer()
    clustered = clusterer.cluster(test_iocs, eps=1.0, min_samples=2)
    
    print("\nClustered IOCs:")
    for ioc in clustered:
        print(f"  [{ioc['cluster_id']:2}] [{ioc['type']:8}] {ioc.get('malware', 'N/A'):15} {ioc['value'][:30]}")
    
    print("\n" + "=" * 60)
    print("Cluster Analysis:")
    print("=" * 60)
    
    analysis = clusterer.analyze_clusters(clustered)
    print(f"\nTotal IOCs: {analysis['total_iocs']}")
    print(f"Clusters found: {analysis['num_clusters']}")
    print(f"Noise points: {analysis['noise_points']}")
    
    for cluster in analysis["clusters"]:
        print(f"\n--- Cluster {cluster['cluster_id']} ({cluster['size']} IOCs) ---")
        print(f"  Campaign: {cluster['potential_campaign']}")
        print(f"  Threat types: {cluster['threat_types']}")
        print(f"  Malware: {cluster['malware_families']}")
        print(f"  Sample IOCs: {cluster['sample_iocs'][:3]}")
