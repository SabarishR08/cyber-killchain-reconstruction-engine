# ingestion/log_parser.py
from datetime import datetime
from ingestion.schemas import NormalizedEvent
from typing import Dict, Any, Optional


TIMESTAMP_FORMATS = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"]


def parse_auth_log(line: Dict[str, Any]) -> Optional[NormalizedEvent]:
    """
    Parse raw auth log dict into normalized event.
    
    Expected input format:
    {
        "timestamp": "2026-01-13 10:15:02",
        "user": "alice",
        "src_ip": "192.168.1.10",
        "status": "FAIL" | "SUCCESS"
    }
    
    Returns:
        NormalizedEvent or None if validation fails
        
    Raises:
        ValueError: If required fields missing or malformed
    """
    required_fields = ["timestamp", "user", "src_ip", "status"]
    
    # Validate required fields
    for field in required_fields:
        if field not in line:
            raise ValueError(f"Missing required field: {field}")
    
    # Validate status
    if line["status"] not in ["FAIL", "SUCCESS"]:
        raise ValueError(f"Invalid status (must be FAIL or SUCCESS): {line['status']}")
    
    # Parse timestamp with multiple formats
    timestamp = None
    for fmt in TIMESTAMP_FORMATS:
        try:
            timestamp = datetime.strptime(line["timestamp"], fmt)
            break
        except ValueError:
            continue
    
    if timestamp is None:
        raise ValueError(f"Invalid timestamp format: {line['timestamp']}")
    
    # Determine event type and severity
    event_type = "login_failed" if line["status"] == "FAIL" else "login_success"
    severity = 6 if line["status"] == "FAIL" else 3
    
    # Build metadata
    metadata = {
        "src_ip": line["src_ip"]
    }
    
    # Preserve any additional fields in metadata
    for key, value in line.items():
        if key not in ["timestamp", "user", "src_ip", "status"]:
            metadata[key] = value

    return NormalizedEvent(
        timestamp=timestamp,
        source="auth",
        event_type=event_type,
        entity=line["user"],
        severity=severity,
        metadata=metadata
    )
