"""
Main collector - orchestrates all threat intel feeds
"""

from collector import urlhaus, feodotracker, threatfox
import json
from datetime import datetime, timezone
from pathlib import Path


def collect_all():
    """Run all collectors and combine results"""
    
    print("=" * 50)
    print("HRTIP Collector - Starting collection run")
    print(f"Time: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 50)
    
    all_iocs = []
    
    # Run each collector
    all_iocs.extend(urlhaus.collect())
    all_iocs.extend(feodotracker.collect())
    all_iocs.extend(threatfox.collect())
    
    print("=" * 50)
    print(f"Total IOCs collected: {len(all_iocs)}")
    print("=" * 50)
    
    return all_iocs


def save_to_file(iocs, output_dir="data"):
    """Save IOCs to a JSON file"""
    
    Path(output_dir).mkdir(exist_ok=True)
    
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/iocs_{timestamp}.json"
    
    with open(filename, "w") as f:
        json.dump(iocs, f, indent=2)
    
    print(f"Saved to: {filename}")
    return filename


if __name__ == "__main__":
    iocs = collect_all()
    save_to_file(iocs)
