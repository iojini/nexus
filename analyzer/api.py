"""
ML Model API Server - serves ML models via FastAPI
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import sys
import os
import json
from pathlib import Path
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.clustering import ThreatClusterer
from analyzer.anomaly_detector import AnomalyDetector
from analyzer.feature_engineering import FeatureEngineer
from processor.enricher import FullEnricher
from processor.scorer import IOCDeduplicator
from processor.mitre_mapper import MITREMapper
from processor.cross_reference import CrossReference

app = FastAPI(
    title="HRTIP ML API",
    description="Healthcare & Retail Threat Intelligence Platform - ML Model Serving API",
    version="1.0.0"
)

# Initialize models
clusterer = ThreatClusterer()
anomaly_detector = AnomalyDetector(contamination=0.1)
feature_engineer = FeatureEngineer()
mitre_mapper = MITREMapper()
deduplicator = IOCDeduplicator()

_enricher = None
_xref = None

def get_enricher():
    global _enricher
    if _enricher is None:
        _enricher = FullEnricher()
    return _enricher

def get_xref():
    global _xref
    if _xref is None:
        _xref = CrossReference()
    return _xref


class IOC(BaseModel):
    type: str
    value: str
    source: Optional[str] = "api"
    threat_type: Optional[str] = None
    malware: Optional[str] = None
    port: Optional[int] = None
    tags: Optional[List[str]] = []
    confidence_score: Optional[int] = None
    first_seen: Optional[str] = None

class IOCList(BaseModel):
    iocs: List[IOC]

class EnrichRequest(BaseModel):
    ioc: IOC
    include_virustotal: bool = True
    include_shodan: bool = True
    include_geoip: bool = True
    include_threat_feeds: bool = True

class AnalyzeRequest(BaseModel):
    iocs: List[IOC]
    include_clustering: bool = True
    include_anomaly_detection: bool = True
    include_features: bool = True
    include_mitre: bool = True


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "HRTIP ML API"}


@app.get("/dashboard-data")
async def get_dashboard_data():
    """Get aggregated data for the dashboard"""
    data_dir = Path("data")
    
    # Load collected IOCs from combined file
    all_iocs = []
    combined_files = sorted(data_dir.glob("iocs_*.json"), reverse=True)
    
    if combined_files:
        with open(combined_files[0]) as f:
            all_iocs = json.load(f)
    
    if not all_iocs:
        return {"error": "No IOC data found. Run collectors first."}
    
    # Build feed status from IOC sources
    source_counts = Counter(ioc.get("source") for ioc in all_iocs)
    feed_status = {}
    for source, count in source_counts.items():
        feed_status[source or "unknown"] = {
            "status": "active",
            "last_run": all_iocs[0].get("collected_at") if all_iocs else None,
            "iocs_collected": count
        }
    
    # Process IOCs using correct method names
    deduped = deduplicator.deduplicate(all_iocs)
    mapped = mitre_mapper.map_multiple(deduped)
    mitre_summary = mitre_mapper.generate_attack_summary(mapped)
    
    clustered = clusterer.cluster(mapped.copy(), eps=1.0, min_samples=2)
    cluster_analysis = clusterer.analyze_clusters(clustered)
    
    anomaly_analysis = anomaly_detector.analyze_anomalies(mapped.copy())
    features = feature_engineer.extract_all_features(mapped)
    
    # Build summary
    sources = Counter(ioc.get("source") for ioc in mapped)
    types = Counter(ioc.get("type") for ioc in mapped)
    threats = Counter(ioc.get("threat_type") for ioc in mapped)
    malware_counts = Counter(ioc.get("malware") for ioc in mapped if ioc.get("malware"))
    
    top_iocs = sorted(mapped, key=lambda x: x.get("confidence_score", 0), reverse=True)[:20]
    
    return {
        "summary": {
            "total_iocs": len(mapped),
            "sources": dict(sources),
            "ioc_types": dict(types),
            "threat_types": dict(threats)
        },
        "top_iocs": [
            {
                "type": ioc.get("type"),
                "value": ioc.get("value"),
                "confidence_score": ioc.get("confidence_score"),
                "malware": ioc.get("malware"),
                "threat_type": ioc.get("threat_type"),
                "sources": ioc.get("corroborated_by", [ioc.get("source")])
            }
            for ioc in top_iocs
        ],
        "mitre_summary": {
            "total_iocs_mapped": mitre_summary.get("total_iocs_mapped", 0),
            "unique_techniques": mitre_summary.get("unique_techniques", 0),
            "unique_tactics": mitre_summary.get("unique_tactics", 0),
            "kill_chain_coverage": features.get("ttp_features", {}).get("kill_chain_coverage", 0),
            "top_techniques": mitre_summary.get("top_techniques", [])[:10],
            "top_tactics": mitre_summary.get("top_tactics", [])[:10],
            "malware_families": list(malware_counts.most_common(10))
        },
        "clusters": cluster_analysis.get("clusters", []),
        "anomalies": {
            "anomalies_found": anomaly_analysis.get("anomalies_found", 0),
            "anomaly_rate": anomaly_analysis.get("anomaly_rate", 0),
            "top_anomalies": [
                {
                    "value": a.get("value"),
                    "type": a.get("type"),
                    "score": a.get("anomaly", {}).get("anomaly_score", 0)
                }
                for a in anomaly_analysis.get("top_anomalies", [])[:5]
            ]
        },
        "feeds": feed_status,
        "temporal": features.get("temporal_features", {}),
    }


@app.post("/enrich")
async def enrich_ioc(request: EnrichRequest):
    try:
        enricher = get_enricher()
        ioc_dict = request.ioc.model_dump()
        enriched = enricher.enrich(ioc_dict)
        return {"status": "success", "enriched_ioc": enriched}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/cross-reference")
async def cross_reference_ioc(ioc: IOC):
    try:
        xref = get_xref()
        result = xref.check_ioc(ioc.type, ioc.value)
        return {"status": "success", "ioc": ioc.model_dump(), "threat_feed_match": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/score")
async def score_ioc(ioc: IOC):
    try:
        scored = deduplicator.scorer.score_ioc(ioc.model_dump())
        return {
            "status": "success",
            "ioc": ioc.value,
            "confidence_score": scored.get("confidence_score"),
            "scoring_factors": scored.get("scoring_factors")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/deduplicate")
async def deduplicate_iocs(request: IOCList):
    try:
        ioc_dicts = [ioc.model_dump() for ioc in request.iocs]
        deduplicated = deduplicator.deduplicate(ioc_dicts)
        stats = deduplicator.get_stats(ioc_dicts, deduplicated)
        return {
            "status": "success",
            "deduplicated_iocs": deduplicated,
            "statistics": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/cluster")
async def cluster_iocs_endpoint(request: IOCList):
    try:
        ioc_dicts = [ioc.model_dump() for ioc in request.iocs]
        clustered = clusterer.cluster(ioc_dicts, eps=1.0, min_samples=2)
        analysis = clusterer.analyze_clusters(clustered)
        return {
            "status": "success",
            "clustered_iocs": clustered,
            "analysis": analysis
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/detect-anomalies")
async def detect_anomalies(request: IOCList):
    try:
        ioc_dicts = [ioc.model_dump() for ioc in request.iocs]
        analysis = anomaly_detector.analyze_anomalies(ioc_dicts)
        return {
            "status": "success",
            "total_iocs": analysis["total_iocs"],
            "anomalies_found": analysis["anomalies_found"],
            "anomaly_rate": analysis["anomaly_rate"],
            "top_anomalies": analysis["top_anomalies"][:10],
            "anomaly_by_type": dict(analysis["anomaly_by_type"]),
            "anomaly_by_source": dict(analysis["anomaly_by_source"])
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/extract-features")
async def extract_features(request: IOCList):
    try:
        ioc_dicts = [ioc.model_dump() for ioc in request.iocs]
        features = feature_engineer.extract_all_features(ioc_dicts)
        return {"status": "success", "features": features}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/map-mitre")
async def map_to_mitre(request: IOCList):
    try:
        ioc_dicts = [ioc.model_dump() for ioc in request.iocs]
        mapped = mitre_mapper.map_multiple(ioc_dicts)
        summary = mitre_mapper.generate_attack_summary(mapped)
        return {
            "status": "success",
            "mapped_iocs": mapped,
            "summary": summary
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze")
async def full_analysis(request: AnalyzeRequest):
    try:
        ioc_dicts = [ioc.model_dump() for ioc in request.iocs]
        
        result = {
            "status": "success",
            "input_count": len(ioc_dicts)
        }
        
        deduplicated = deduplicator.deduplicate(ioc_dicts)
        result["deduplicated_count"] = len(deduplicated)
        result["dedup_stats"] = deduplicator.get_stats(ioc_dicts, deduplicated)
        
        if request.include_mitre:
            mapped = mitre_mapper.map_multiple(deduplicated)
            result["mitre_summary"] = mitre_mapper.generate_attack_summary(mapped)
            deduplicated = mapped
        
        if request.include_clustering:
            clustered = clusterer.cluster(deduplicated.copy(), eps=1.0, min_samples=2)
            result["clustering"] = clusterer.analyze_clusters(clustered)
        
        if request.include_anomaly_detection:
            anomaly_analysis = anomaly_detector.analyze_anomalies(deduplicated.copy())
            result["anomaly_detection"] = {
                "anomalies_found": anomaly_analysis["anomalies_found"],
                "anomaly_rate": anomaly_analysis["anomaly_rate"],
                "top_anomalies": [
                    {"value": a.get("value"), "type": a.get("type"), "score": a.get("anomaly", {}).get("anomaly_score")}
                    for a in anomaly_analysis["top_anomalies"][:5]
                ],
                "by_type": dict(anomaly_analysis["anomaly_by_type"]),
                "by_source": dict(anomaly_analysis["anomaly_by_source"])
            }
        
        if request.include_features:
            result["features"] = feature_engineer.extract_all_features(deduplicated)
        
        result["top_iocs"] = [
            {
                "type": ioc.get("type"),
                "value": ioc.get("value"),
                "confidence_score": ioc.get("confidence_score"),
                "malware": ioc.get("malware"),
                "threat_type": ioc.get("threat_type")
            }
            for ioc in sorted(deduplicated, key=lambda x: x.get("confidence_score", 0), reverse=True)[:10]
        ]
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    print("Starting HRTIP ML API Server...")
    print("API Documentation: http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)
