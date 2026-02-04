"""
Anomaly Detector - identifies unusual patterns in telemetry/IOC data
Uses Isolation Forest for detecting outliers
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime, timezone
from typing import List, Dict
from collections import Counter


class AnomalyDetector:
    """Detects anomalous IOCs and network activity"""
    
    def __init__(self, contamination: float = 0.1):
        """
        Args:
            contamination: Expected proportion of anomalies (0.0 to 0.5)
        """
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
    
    def extract_features(self, iocs: List[Dict]) -> np.ndarray:
        """Extract features for anomaly detection"""
        
        features = []
        
        # Calculate global statistics for relative features
        all_ports = [ioc.get("port", 0) for ioc in iocs if ioc.get("port")]
        port_mean = np.mean(all_ports) if all_ports else 0
        port_std = np.std(all_ports) if all_ports else 1
        
        source_counts = Counter(ioc.get("source", "unknown") for ioc in iocs)
        total_iocs = len(iocs)
        
        for ioc in iocs:
            feature_vec = []
            
            # 1. Source rarity (rare sources might be anomalous)
            source = ioc.get("source", "unknown")
            source_freq = source_counts.get(source, 1) / total_iocs
            feature_vec.append(1 - source_freq)  # Rarer = higher value
            
            # 2. Port anomaly (unusual ports)
            port = ioc.get("port", 0)
            if port and port_std > 0:
                port_zscore = abs(port - port_mean) / port_std
                feature_vec.append(min(port_zscore, 5) / 5)
            else:
                feature_vec.append(0)
            
            # 3. High port number (ephemeral ports can be suspicious)
            feature_vec.append(1 if port > 49152 else 0)
            
            # 4. Non-standard port for type
            ioc_type = ioc.get("type", "")
            threat_type = ioc.get("threat_type", "")
            
            standard_ports = {
                "botnet_c2": [80, 443, 8080, 8443, 4444],
                "phishing": [80, 443],
                "malware_download": [80, 443, 8080],
            }
            
            if port and threat_type in standard_ports:
                feature_vec.append(0 if port in standard_ports[threat_type] else 1)
            else:
                feature_vec.append(0)
            
            # 5. Confidence score (low confidence = potentially anomalous)
            confidence = ioc.get("confidence_score", 50)
            feature_vec.append(1 - (confidence / 100))
            
            # 6. IP-specific features
            value = str(ioc.get("value", ""))
            if ioc_type == "ipv4":
                octets = value.split(".")
                if len(octets) == 4:
                    # Unusual first octet ranges
                    first_octet = int(octets[0])
                    unusual_ranges = list(range(0, 10)) + list(range(224, 256))
                    feature_vec.append(1 if first_octet in unusual_ranges else 0)
                else:
                    feature_vec.append(0)
            else:
                feature_vec.append(0)
            
            # 7. Domain entropy (high entropy = DGA-like)
            if ioc_type == "domain":
                entropy = self._calculate_entropy(value)
                feature_vec.append(min(entropy / 4, 1))  # Normalize
            else:
                feature_vec.append(0)
            
            # 8. Domain length anomaly
            if ioc_type == "domain":
                # Very long or very short domains can be suspicious
                length = len(value)
                if length < 5 or length > 40:
                    feature_vec.append(1)
                else:
                    feature_vec.append(0)
            else:
                feature_vec.append(0)
            
            # 9. Numeric domain (DGA indicator)
            if ioc_type == "domain":
                num_ratio = sum(c.isdigit() for c in value) / len(value) if value else 0
                feature_vec.append(num_ratio)
            else:
                feature_vec.append(0)
            
            # 10. Missing malware family (could be unknown threat)
            feature_vec.append(0 if ioc.get("malware") else 1)
            
            features.append(feature_vec)
        
        return np.array(features)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0
        
        freq = Counter(text)
        length = len(text)
        entropy = -sum((count/length) * np.log2(count/length) for count in freq.values())
        return entropy
    
    def fit(self, iocs: List[Dict]):
        """Fit the anomaly detector on baseline IOCs"""
        
        if len(iocs) < 10:
            print("[AnomalyDetector] Warning: Small dataset, results may be unreliable")
        
        features = self.extract_features(iocs)
        features_scaled = self.scaler.fit_transform(features)
        self.model.fit(features_scaled)
        self.is_fitted = True
    
    def detect(self, iocs: List[Dict]) -> List[Dict]:
        """
        Detect anomalies in IOCs
        
        Returns IOCs with anomaly scores and labels
        """
        
        if not self.is_fitted:
            # Fit on the same data if not fitted
            self.fit(iocs)
        
        features = self.extract_features(iocs)
        features_scaled = self.scaler.transform(features)
        
        # Get predictions (-1 = anomaly, 1 = normal)
        predictions = self.model.predict(features_scaled)
        
        # Get anomaly scores (lower = more anomalous)
        scores = self.model.decision_function(features_scaled)
        
        # Normalize scores to 0-100 (higher = more anomalous)
        min_score, max_score = scores.min(), scores.max()
        if max_score > min_score:
            normalized_scores = 100 * (1 - (scores - min_score) / (max_score - min_score))
        else:
            normalized_scores = np.full_like(scores, 50)
        
        # Add results to IOCs
        for i, ioc in enumerate(iocs):
            ioc["anomaly"] = {
                "is_anomaly": predictions[i] == -1,
                "anomaly_score": round(float(normalized_scores[i]), 1),
                "raw_score": round(float(scores[i]), 4)
            }
        
        return iocs
    
    def get_anomalies(self, iocs: List[Dict]) -> List[Dict]:
        """Get only the anomalous IOCs"""
        detected = self.detect(iocs)
        return [ioc for ioc in detected if ioc.get("anomaly", {}).get("is_anomaly")]
    
    def analyze_anomalies(self, iocs: List[Dict]) -> Dict:
        """Analyze detected anomalies"""
        
        detected = self.detect(iocs)
        anomalies = [ioc for ioc in detected if ioc.get("anomaly", {}).get("is_anomaly")]
        
        analysis = {
            "total_iocs": len(detected),
            "anomalies_found": len(anomalies),
            "anomaly_rate": round(len(anomalies) / len(detected) * 100, 1) if detected else 0,
            "top_anomalies": sorted(
                anomalies,
                key=lambda x: x.get("anomaly", {}).get("anomaly_score", 0),
                reverse=True
            )[:10],
            "anomaly_by_type": Counter(a.get("type") for a in anomalies),
            "anomaly_by_source": Counter(a.get("source") for a in anomalies),
        }
        
        return analysis


if __name__ == "__main__":
    print("=" * 60)
    print("Anomaly Detector - Testing")
    print("=" * 60)
    
    # Test IOCs - mix of normal and anomalous
    test_iocs = [
        # Normal C2 activity
        {"type": "ipv4", "value": "45.33.32.156", "source": "feodotracker", "threat_type": "botnet_c2", "port": 443, "confidence_score": 85, "malware": "Emotet"},
        {"type": "ipv4", "value": "162.243.103.246", "source": "feodotracker", "threat_type": "botnet_c2", "port": 8080, "confidence_score": 90, "malware": "Emotet"},
        {"type": "ipv4", "value": "185.220.101.34", "source": "threatfox", "threat_type": "botnet_c2", "port": 443, "confidence_score": 80, "malware": "QakBot"},
        
        # Normal phishing
        {"type": "url", "value": "http://fake-bank.com/login", "source": "openphish", "threat_type": "phishing", "confidence_score": 75},
        {"type": "domain", "value": "secure-paypal.xyz", "source": "openphish", "threat_type": "phishing", "confidence_score": 70},
        
        # Normal malware
        {"type": "sha256", "value": "a" * 64, "source": "malwarebazaar", "threat_type": "malware", "confidence_score": 85, "malware": "Mirai"},
        {"type": "sha256", "value": "b" * 64, "source": "malwarebazaar", "threat_type": "malware", "confidence_score": 80, "malware": "Mirai"},
        
        # ANOMALIES
        # Unusual port
        {"type": "ipv4", "value": "192.0.2.100", "source": "feodotracker", "threat_type": "botnet_c2", "port": 31337, "confidence_score": 40},
        # DGA-like domain (high entropy, numeric)
        {"type": "domain", "value": "x7k9m2p4q8.xyz", "source": "alienvault_otx", "threat_type": "malware", "confidence_score": 30},
        # Unknown source, low confidence
        {"type": "ipv4", "value": "198.51.100.50", "source": "unknown", "threat_type": "botnet_c2", "port": 65000, "confidence_score": 20},
        # Very long domain
        {"type": "domain", "value": "this-is-a-very-long-suspicious-domain-name-that-looks-malicious.tk", "source": "threatfox", "threat_type": "phishing", "confidence_score": 25},
    ]
    
    detector = AnomalyDetector(contamination=0.2)
    analysis = detector.analyze_anomalies(test_iocs)
    
    print(f"\nTotal IOCs: {analysis['total_iocs']}")
    print(f"Anomalies found: {analysis['anomalies_found']}")
    print(f"Anomaly rate: {analysis['anomaly_rate']}%")
    
    print("\n" + "-" * 60)
    print("Top Anomalies:")
    print("-" * 60)
    
    for ioc in analysis["top_anomalies"][:5]:
        anomaly = ioc.get("anomaly", {})
        print(f"\n  [{ioc['type']}] {ioc['value'][:40]}")
        print(f"    Anomaly Score: {anomaly.get('anomaly_score')}/100")
        print(f"    Source: {ioc.get('source')}, Port: {ioc.get('port', 'N/A')}")
        print(f"    Confidence: {ioc.get('confidence_score', 'N/A')}")
    
    print("\n" + "-" * 60)
    print(f"Anomalies by type: {dict(analysis['anomaly_by_type'])}")
    print(f"Anomalies by source: {dict(analysis['anomaly_by_source'])}")
