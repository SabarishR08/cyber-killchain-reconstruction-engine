# correlation/rules.py
from datetime import timedelta
from ingestion.schemas import NormalizedEvent
from typing import List


# Configuration-driven detection parameters
CORRELATION_CONFIG = {
    "brute_force_threshold": 3,
    "credential_compromise_threshold": 2,
    "time_window_minutes": 10,
    "confidence_weights": {
        "brute_force": 0.8,
        "credential_compromise": 1.0
    }
}

FAILED_LOGIN_THRESHOLD = CORRELATION_CONFIG["brute_force_threshold"]
TIME_WINDOW = timedelta(minutes=CORRELATION_CONFIG["time_window_minutes"])


def is_bruteforce(events: List[NormalizedEvent]) -> bool:
    """Detect brute force: multiple failed logins within time window."""
    failed = [e for e in events if e.event_type == "login_failed"]
    return len(failed) >= FAILED_LOGIN_THRESHOLD


def is_credential_compromise(events: List[NormalizedEvent]) -> bool:
    """Detect credential compromise: failed login followed by success."""
    failed_then_success = False
    for i in range(len(events) - 1):
        if events[i].event_type == "login_failed" and events[i + 1].event_type == "login_success":
            failed_then_success = True
            break
    return failed_then_success


# ── Network-Traffic-Specific Rules (added for SIH26153) ──


def is_portscan_to_exploit(events: List[NormalizedEvent]) -> bool:
    """
    Rule 1 — Port-Scan-to-Exploit-Attempt Sequence.

    Detects when a port_scan_detected event is followed within the same
    time window by a brute_force_attempt or suspicious_connection from
    the same source IP. This is the classic recon → exploitation kill chain
    progression observed in real network attacks.
    """
    scan_events = [e for e in events if e.event_type == "port_scan_detected"]
    exploit_events = [
        e for e in events
        if e.event_type in ("brute_force_attempt", "suspicious_connection")
    ]

    if not scan_events or not exploit_events:
        return False

    # Check that scan happened before exploit, from same source
    for scan in scan_events:
        for exploit in exploit_events:
            scan_ip = scan.metadata.get("src_ip", "")
            exploit_ip = exploit.metadata.get("src_ip", "")
            if scan_ip == exploit_ip and scan.timestamp <= exploit.timestamp:
                return True

    return False


def is_dos_traffic_spike(events: List[NormalizedEvent]) -> bool:
    """
    Rule 2 — DoS / Traffic-Volume Spike.

    Detects a potential Denial-of-Service pattern when a single source IP
    generates a high volume of connection attempts (connection_cycling) or
    when multiple anomalies are detected from the same source in rapid
    succession, indicating traffic flooding.

    Threshold: 3+ network anomalies from the same IP within the window,
    or 1+ connection_cycling events with 50+ total packets in metadata.
    """
    network_events = [
        e for e in events
        if e.source == "network"
    ]

    if not network_events:
        return False

    # Group by source IP
    from collections import defaultdict
    ip_events = defaultdict(list)
    for e in network_events:
        ip = e.metadata.get("src_ip", e.entity)
        ip_events[ip].append(e)

    for ip, ip_evts in ip_events.items():
        # Check 1: 3+ network anomalies from same IP
        if len(ip_evts) >= 3:
            return True

        # Check 2: connection_cycling with high packet count
        cycling_events = [e for e in ip_evts if e.event_type == "connection_cycling"]
        if cycling_events:
            total_packets = sum(
                e.metadata.get("total_packets", e.metadata.get("connections_in_window", 0))
                for e in cycling_events
            )
            if total_packets >= 50:
                return True

        # Check 3: Multiple anomaly types from same IP (multi-vector attack)
        event_types = set(e.event_type for e in ip_evts)
        if len(event_types) >= 2 and len(ip_evts) >= 2:
            return True

    return False
