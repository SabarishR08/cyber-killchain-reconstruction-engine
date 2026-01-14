# test_day2.py
import json
from datetime import datetime
from datastore.db import initialize_db, get_connection
from datastore.models import insert_event
from ingestion.log_parser import parse_auth_log
from ingestion.schemas import NormalizedEvent
from correlation.correlator import correlate_events


def fetch_events():
    """Retrieve all events from database."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, source, event_type, entity, severity, metadata FROM events")
    rows = cursor.fetchall()
    conn.close()

    events = []
    for row in rows:
        events.append(
            NormalizedEvent(
                timestamp=datetime.fromisoformat(row[0]),
                source=row[1],
                event_type=row[2],
                entity=row[3],
                severity=row[4],
                metadata=json.loads(row[5])
            )
        )
    return events


def test_credential_compromise():
    """Test credential compromise pattern detection."""
    print("\n[TEST] Credential Compromise Pattern")
    print("=" * 60)
    
    # Clear database
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM events')
    conn.commit()
    conn.close()
    
    # Add test events
    logs = [
        {'timestamp': '2026-01-13 14:00:00', 'user': 'bob', 'src_ip': '10.0.0.5', 'status': 'FAIL'},
        {'timestamp': '2026-01-13 14:00:30', 'user': 'bob', 'src_ip': '10.0.0.5', 'status': 'SUCCESS'},
    ]
    
    for log in logs:
        event = parse_auth_log(log)
        insert_event(event)
    
    # Correlate
    events = fetch_events()
    incidents = correlate_events(events)
    
    if incidents:
        print(f"Pattern Detected: {incidents[0]['pattern']}")
        print(f"Kill Chain Stage: {incidents[0]['kill_chain_stage']}")
        print(f"Entity: {incidents[0]['entity']}")
    else:
        print("No incidents detected")


def test_brute_force():
    """Test brute force pattern detection."""
    print("\n[TEST] Brute Force Pattern")
    print("=" * 60)
    
    # Clear database
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM events')
    conn.commit()
    conn.close()
    
    # Add test events
    logs = [
        {'timestamp': '2026-01-13 15:00:00', 'user': 'charlie', 'src_ip': '192.168.1.50', 'status': 'FAIL'},
        {'timestamp': '2026-01-13 15:00:15', 'user': 'charlie', 'src_ip': '192.168.1.50', 'status': 'FAIL'},
        {'timestamp': '2026-01-13 15:00:30', 'user': 'charlie', 'src_ip': '192.168.1.50', 'status': 'FAIL'},
    ]
    
    for log in logs:
        event = parse_auth_log(log)
        insert_event(event)
    
    # Correlate
    events = fetch_events()
    incidents = correlate_events(events)
    
    if incidents:
        print(f"Pattern Detected: {incidents[0]['pattern']}")
        print(f"Kill Chain Stage: {incidents[0]['kill_chain_stage']}")
        print(f"Entity: {incidents[0]['entity']}")
        print(f"Failed Attempts: {sum(1 for e in incidents[0]['events'] if e.event_type == 'login_failed')}")
    else:
        print("No incidents detected")


if __name__ == "__main__":
    initialize_db()
    test_brute_force()
    test_credential_compromise()
    print("\n[+] Day 2 tests complete")
