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
