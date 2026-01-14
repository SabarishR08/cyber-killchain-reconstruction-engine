# main.py
import json
import sys
import argparse
from datetime import datetime
from datastore.db import initialize_db, get_connection
from datastore.models import insert_event
from ingestion.log_parser import parse_auth_log
from ingestion.schemas import NormalizedEvent
from correlation.correlator import correlate_events
from correlation.rules import is_bruteforce, is_credential_compromise
from graph.attack_graph import build_attack_graph, print_attack_graph
from reporting.timeline import build_timeline, print_timeline
from reporting.attribution import generate_incident_report
from reporting.scoring import prioritize_incidents


def fetch_events():
    """Retrieve all events from database and convert to NormalizedEvent objects."""
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


def load_sample_logs():
    """Load sample auth logs for demonstration."""
    return [
        {
            "timestamp": "2026-01-13 10:15:02",
            "user": "alice",
            "src_ip": "192.168.1.10",
            "status": "FAIL"
        },
        {
            "timestamp": "2026-01-13 10:15:45",
            "user": "alice",
            "src_ip": "192.168.1.10",
            "status": "FAIL"
        },
        {
            "timestamp": "2026-01-13 10:16:12",
            "user": "alice",
            "src_ip": "192.168.1.10",
            "status": "FAIL"
        },
        {
            "timestamp": "2026-01-13 10:16:45",
            "user": "alice",
            "src_ip": "192.168.1.10",
            "status": "SUCCESS"
        }
    ]


def ingest_logs(log_file=None):
    """Ingest logs from file or use samples."""
    print("[*] Initializing database...")
    initialize_db()
    
    if log_file:
        print(f"[*] Loading logs from {log_file}...")
        try:
            with open(log_file, 'r') as f:
                logs = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[!] Error reading log file: {e}")
            sys.exit(1)
    else:
        print("[*] Using sample logs...")
        logs = load_sample_logs()
    
    print(f"[*] Ingesting {len(logs)} events...")
    inserted = 0
    for log in logs:
        try:
            event = parse_auth_log(log)
            event_id = insert_event(event)
            if event_id:
                inserted += 1
        except (ValueError, TypeError) as e:
            print(f"[!] Skipped invalid event: {e}")
    
    print(f"[+] {inserted}/{len(logs)} events ingested successfully\n")
    return inserted > 0


def analyze():
    """Correlate events and detect incidents."""
    print("[*] Fetching events from database...")
    events = fetch_events()
    
    if not events:
        print("[!] No events found in database")
        return []
    
    print(f"[+] {len(events)} events loaded")
    
    print("[*] Correlating events and detecting patterns...")
    incidents = correlate_events(events)
    print(f"[+] {len(incidents)} incidents detected\n")
    
    return incidents


def report(incidents):
    """Generate and display incident report."""
    if not incidents:
        print("[!] No incidents to report")
        return
    
    print("[*] Generating incident reports...")
    
    # Enrich incidents with full metadata
    enriched_incidents = []
    for i, incident in enumerate(incidents):
        events = incident.get('events', [])
        
        enriched = {
            'incident_id': f'incident_{i:03d}',
            'entity': incident['entity'],
            'pattern_type': incident.get('pattern', 'unknown').lower().replace(' ', '_'),
            'kill_chain_stage': incident.get('kill_chain_stage', 'Unknown'),
            'severity': 'HIGH' if is_bruteforce(incident.get('events', [])) or is_credential_compromise(incident.get('events', [])) else 'MEDIUM',
            'confidence': 1.0,
            'risk_score': 85,
            'priority': 'HIGH',
            'event_count': len(events)
        }
        enriched_incidents.append(enriched)
    
    # Prioritize incidents
    prioritized = sorted(enriched_incidents, key=lambda x: x['risk_score'], reverse=True)
    
    print("\n" + "=" * 70)
    print("INCIDENT SUMMARY")
    print("=" * 70)
    
    for incident in prioritized:
        print(f"\nIncident ID: {incident['incident_id']}")
        print(f"Entity: {incident['entity']}")
        print(f"Pattern: {incident['pattern_type']}")
        print(f"Kill Chain: {incident['kill_chain_stage']}")
        print(f"Severity: {incident['severity']}")
        print(f"Confidence: {incident['confidence']:.1%}")
        print(f"Risk Score: {incident['risk_score']}/100")
        print(f"Priority: {incident['priority']}")
        print(f"Events: {incident['event_count']}")
    
    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Cyber Kill Chain Reconstruction Engine"
    )
    parser.add_argument(
        '--ingest',
        nargs='?',
        const='samples',
        metavar='FILE',
        help='Ingest logs from JSON file (or use samples if not provided)'
    )
    parser.add_argument(
        '--analyze',
        action='store_true',
        help='Correlate stored events and detect incidents'
    )
    parser.add_argument(
        '--report',
        action='store_true',
        help='Generate incident report'
    )
    
    args = parser.parse_args()
    
    # Default: run full pipeline
    if not args.ingest and not args.analyze and not args.report:
        args.ingest = 'samples'
        args.analyze = True
        args.report = True
    
    incidents = []
    
    if args.ingest:
        ingest_logs(args.ingest if args.ingest != 'samples' else None)
    
    if args.analyze:
        incidents = analyze()
    
    if args.report:
        report(incidents if incidents else analyze())


if __name__ == "__main__":
    main()
