"""
Telemetry Ingest - accepts syslog, CEF, and JSON security logs
Simulates what a SIEM would forward to the threat intel platform
"""

import json
import re
from datetime import datetime, timezone
from typing import List, Dict, Optional


def parse_json_log(log_line: str) -> Optional[Dict]:
    """Parse JSON-formatted security log"""
    try:
        data = json.loads(log_line)
        return {
            "format": "json",
            "timestamp": data.get("timestamp", data.get("@timestamp", data.get("time"))),
            "source_ip": data.get("src_ip", data.get("source_ip", data.get("srcip"))),
            "dest_ip": data.get("dst_ip", data.get("dest_ip", data.get("dstip"))),
            "source_port": data.get("src_port", data.get("source_port")),
            "dest_port": data.get("dst_port", data.get("dest_port")),
            "action": data.get("action", data.get("event_type")),
            "severity": data.get("severity", data.get("level")),
            "message": data.get("message", data.get("msg")),
            "raw": log_line
        }
    except json.JSONDecodeError:
        return None


def parse_cef_log(log_line: str) -> Optional[Dict]:
    """Parse CEF (Common Event Format) log"""
    # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    cef_pattern = r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)"
    match = re.match(cef_pattern, log_line)
    
    if not match:
        return None
    
    version, vendor, product, dev_version, sig_id, name, severity, extension = match.groups()
    
    # Parse extension key=value pairs
    ext_dict = {}
    ext_pattern = r"(\w+)=([^\s]+(?:\s+(?!\w+=)[^\s]+)*)"
    for key, value in re.findall(ext_pattern, extension):
        ext_dict[key] = value
    
    return {
        "format": "cef",
        "cef_version": version,
        "vendor": vendor,
        "product": product,
        "signature_id": sig_id,
        "name": name,
        "severity": severity,
        "source_ip": ext_dict.get("src"),
        "dest_ip": ext_dict.get("dst"),
        "source_port": ext_dict.get("spt"),
        "dest_port": ext_dict.get("dpt"),
        "message": name,
        "extension": ext_dict,
        "raw": log_line
    }


def parse_syslog(log_line: str) -> Optional[Dict]:
    """Parse syslog format"""
    # RFC 3164 syslog: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
    # RFC 5424 syslog: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    
    # Try RFC 3164 first
    rfc3164_pattern = r"<(\d+)>(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?):\s*(.*)"
    match = re.match(rfc3164_pattern, log_line)
    
    if match:
        pri, timestamp, hostname, tag, message = match.groups()
        priority = int(pri)
        facility = priority >> 3
        severity = priority & 0x07
        
        return {
            "format": "syslog_rfc3164",
            "priority": priority,
            "facility": facility,
            "severity": severity,
            "timestamp": timestamp,
            "hostname": hostname,
            "tag": tag,
            "message": message,
            "raw": log_line
        }
    
    # Try simplified syslog
    simple_pattern = r"(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.*)"
    match = re.match(simple_pattern, log_line)
    
    if match:
        timestamp, hostname, message = match.groups()
        return {
            "format": "syslog_simple",
            "timestamp": timestamp,
            "hostname": hostname,
            "message": message,
            "raw": log_line
        }
    
    return None


def parse_log(log_line: str) -> Optional[Dict]:
    """Auto-detect and parse log format"""
    log_line = log_line.strip()
    
    if not log_line:
        return None
    
    # Try JSON first
    if log_line.startswith("{"):
        result = parse_json_log(log_line)
        if result:
            return result
    
    # Try CEF
    if log_line.startswith("CEF:"):
        result = parse_cef_log(log_line)
        if result:
            return result
    
    # Try syslog
    result = parse_syslog(log_line)
    if result:
        return result
    
    # Return as raw if no format matched
    return {
        "format": "unknown",
        "message": log_line,
        "raw": log_line
    }


def ingest_logs(logs: List[str]) -> List[Dict]:
    """Ingest multiple log lines"""
    results = []
    
    for log_line in logs:
        parsed = parse_log(log_line)
        if parsed:
            parsed["ingested_at"] = datetime.now(timezone.utc).isoformat()
            results.append(parsed)
    
    return results


def extract_iocs_from_logs(parsed_logs: List[Dict]) -> List[Dict]:
    """Extract IOCs from parsed logs"""
    iocs = []
    seen = set()
    
    for log in parsed_logs:
        # Extract IPs
        for field in ["source_ip", "dest_ip"]:
            ip = log.get(field)
            if ip and ip not in seen:
                seen.add(ip)
                iocs.append({
                    "type": "ip",
                    "value": ip,
                    "source": "telemetry",
                    "context": log.get("message", "")[:100]
                })
    
    return iocs


if __name__ == "__main__":
    # Test with sample logs
    sample_logs = [
        # JSON format (Elastic/Splunk style)
        '{"timestamp": "2026-02-03T10:30:00Z", "src_ip": "45.33.32.156", "dst_ip": "10.0.0.50", "action": "blocked", "severity": "high", "message": "Malware C2 communication detected"}',
        
        # CEF format (common in SIEM)
        'CEF:0|Security|Firewall|1.0|100|Malicious Connection|9|src=185.220.101.34 dst=192.168.1.100 spt=443 dpt=8080 msg=Botnet C2 detected',
        
        # Syslog format
        '<134>Feb  3 10:30:00 fw01 snort: [1:2024:1] MALWARE-CNC Win.Trojan.Emotet variant outbound connection [Classification: A Network Trojan was Detected] [Priority: 1] {TCP} 10.0.0.25:49152 -> 162.243.103.246:8080',
        
        # Simple syslog
        'Feb  3 10:31:00 ids01 suricata: Alert - ET MALWARE Possible Ransomware C2 Activity - src 10.0.0.30 dst 45.33.32.156',
    ]
    
    print("=" * 60)
    print("HRTIP Telemetry Ingest - Testing log parsers")
    print("=" * 60)
    
    parsed = ingest_logs(sample_logs)
    
    for i, log in enumerate(parsed, 1):
        print(f"\n--- Log {i} ({log['format']}) ---")
        for key, value in log.items():
            if key != "raw" and value:
                print(f"  {key}: {value}")
    
    print("\n" + "=" * 60)
    print("Extracted IOCs from logs:")
    print("=" * 60)
    
    iocs = extract_iocs_from_logs(parsed)
    for ioc in iocs:
        print(f"  [{ioc['type']}] {ioc['value']}")
    
    print(f"\nTotal: {len(parsed)} logs parsed, {len(iocs)} IOCs extracted")
