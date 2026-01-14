# test_day3.py
import json
from datetime import datetime
from datastore.db import initialize_db, get_connection
from datastore.models import insert_event
from ingestion.log_parser import parse_auth_log
from ingestion.schemas import NormalizedEvent
from correlation.correlator import correlate_events
from graph.attack_graph import build_attack_graph, print_attack_graph
from reporting.timeline import print_timeline, get_timeline_stats
from reporting.attribution import generate_incident_report


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


def test_attack_graph_and_timeline():
    """Test Day 3: Attack graph and timeline reconstruction."""
    print("\n" + "=" * 70)
    print("DAY 3 TEST: ATTACK GRAPH & TIMELINE RECONSTRUCTION")
    print("=" * 70)
    
    # Clear database
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM events')
    conn.commit()
    conn.close()
    
    # Scenario: Credential compromise attack
    logs = [
        {'timestamp': '2026-01-14 09:00:00', 'user': 'alice', 'src_ip': '192.168.1.100', 'status': 'FAIL'},
        {'timestamp': '2026-01-14 09:00:15', 'user': 'alice', 'src_ip': '192.168.1.100', 'status': 'FAIL'},
        {'timestamp': '2026-01-14 09:00:30', 'user': 'alice', 'src_ip': '192.168.1.100', 'status': 'SUCCESS'},
    ]
    
    print("\n[STEP 1] Ingesting logs...")
    for log in logs:
        event = parse_auth_log(log)
        insert_event(event)
    print(f"[+] {len(logs)} events ingested")
    
    # Fetch and correlate
    print("\n[STEP 2] Correlating events...")
    events = fetch_events()
    incidents = correlate_events(events)
    print(f"[+] {len(incidents)} incident(s) detected")
    
    if not incidents:
        print("[-] No incidents detected. Exiting.")
        return
    
    incident = incidents[0]
    
    # Generate incident report
    print("\n[STEP 3] Generating incident report...")
    report = generate_incident_report(incident)
    print(f"\nIncident Summary:")
    print(f"  Entity: {report['summary']['entity']}")
    print(f"  Pattern: {report['summary']['pattern']}")
    print(f"  Kill Chain Stage: {report['summary']['kill_chain_stage']}")
    print(f"  Event Count: {report['summary']['event_count']}")
    print(f"  Confidence: {report['summary']['confidence']}")
    print(f"  Severity: {report['severity']}")
    
    # Build and display attack graph
    print("\n[STEP 4] Constructing attack graph...")
    graph = build_attack_graph(incident)
    print_attack_graph(graph, f"Incident: {incident['pattern']}")
    
    # Build and display timeline
    print("\n[STEP 5] Reconstructing incident timeline...")
    print_timeline(incident["events"], f"Incident: {incident['pattern']}")
    
    # Timeline stats
    stats = get_timeline_stats(incident["events"])
    print(f"Timeline Statistics:")
    print(f"  Total Events: {stats['total_events']}")
    print(f"  Event Types: {stats['event_types']}")
    print(f"  Duration: {stats['start_time']} → {stats['end_time']}")


if __name__ == "__main__":
    initialize_db()
    test_attack_graph_and_timeline()
    print("\n[+] Day 3 test complete")
