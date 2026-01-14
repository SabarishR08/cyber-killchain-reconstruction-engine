# test_day4.py
import json
from datetime import datetime
from datastore.db import initialize_db, get_connection
from datastore.models import insert_event
from ingestion.log_parser import parse_auth_log
from ingestion.schemas import NormalizedEvent
from correlation.correlator import correlate_events
from graph.attack_graph import build_attack_graph, print_attack_graph
from reporting.timeline import build_timeline
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


def build_enriched_incident(incident, events):
    """Build a fully enriched incident object with all Day 4 data."""
    report = generate_incident_report(incident)
    
    enriched = {
        # Core incident info
        "entity": incident["entity"],
        "pattern": incident["pattern"],
        "kill_chain_stage": incident["kill_chain_stage"],
        "event_count": incident["event_count"],
        
        # Scoring and assessment
        "confidence": report["summary"]["confidence"],
        "severity": report["severity"],
        "attribution": report["attribution"],
        
        # MITRE enrichment
        "mitre": report["mitre"],
        
        # Analyst explanation
        "explanation": report["explanation"],
        
        # Timeline
        "timeline": build_timeline(incident["events"]),
        
        # Attack graph
        "graph": {
            "nodes": len(build_attack_graph(incident).nodes()),
            "edges": len(build_attack_graph(incident).edges()),
        },
        
        # Raw events for forensics
        "event_count_breakdown": {
            "login_failed": sum(1 for e in incident["events"] if e.event_type == "login_failed"),
            "login_success": sum(1 for e in incident["events"] if e.event_type == "login_success"),
        }
    }
    
    return enriched


def test_credential_compromise_enrichment():
    """Test Day 4: Threat attribution and MITRE enrichment."""
    print("\n" + "=" * 70)
    print("DAY 4 TEST: THREAT ATTRIBUTION & MITRE ENRICHMENT")
    print("=" * 70)
    
    # Clear database
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM events')
    conn.commit()
    conn.close()
    
    # Scenario: Targeted credential compromise
    logs = [
        {'timestamp': '2026-01-14 11:00:00', 'user': 'alice', 'src_ip': '192.168.1.100', 'status': 'FAIL'},
        {'timestamp': '2026-01-14 11:00:15', 'user': 'alice', 'src_ip': '192.168.1.100', 'status': 'FAIL'},
        {'timestamp': '2026-01-14 11:00:30', 'user': 'alice', 'src_ip': '192.168.1.100', 'status': 'SUCCESS'},
    ]
    
    print("\n[STEP 1] Ingesting logs...")
    for log in logs:
        event = parse_auth_log(log)
        insert_event(event)
    print(f"[+] {len(logs)} events ingested")
    
    # Correlate
    print("\n[STEP 2] Correlating events...")
    events = fetch_events()
    incidents = correlate_events(events)
    print(f"[+] {len(incidents)} incident(s) detected")
    
    if not incidents:
        print("[-] No incidents. Exiting.")
        return
    
    incident = incidents[0]
    
    # Enrich with Day 4 data
    print("\n[STEP 3] Enriching with threat attribution...")
    enriched = build_enriched_incident(incident, events)
    
    # Display enriched incident
    print("\n" + "=" * 70)
    print("FULLY ENRICHED INCIDENT OBJECT (Day 4)")
    print("=" * 70)
    print(json.dumps(enriched, indent=2, default=str))
    
    print("\n" + "=" * 70)
    print("PARSED INCIDENT SUMMARY")
    print("=" * 70)
    print(f"\nEntity: {enriched['entity']}")
    print(f"Pattern: {enriched['pattern']}")
    print(f"Kill Chain Stage: {enriched['kill_chain_stage']}")
    print(f"Event Count: {enriched['event_count']}")
    print(f"Confidence: {int(enriched['confidence'] * 100)}%")
    print(f"Severity: {enriched['severity']}")
    print(f"\nMITRE Enrichment:")
    print(f"  Technique: {enriched['mitre']['technique_id']} - {enriched['mitre']['technique_name']}")
    print(f"  Tactic: {enriched['mitre']['tactic']}")
    print(f"  Description: {enriched['mitre']['description']}")
    print(f"\nThreat Attribution: {enriched['attribution']}")
    print(f"\nExplanation:\n  {enriched['explanation']}")


def test_brute_force_enrichment():
    """Test Day 4 with brute force scenario (automated attack)."""
    print("\n" + "=" * 70)
    print("DAY 4 TEST: BRUTE FORCE WITH MITRE ENRICHMENT")
    print("=" * 70)
    
    # Clear database
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM events')
    conn.commit()
    conn.close()
    
    # Scenario: Automated brute force from multiple IPs
    logs = [
        {'timestamp': '2026-01-14 12:00:00', 'user': 'admin', 'src_ip': '10.0.0.1', 'status': 'FAIL'},
        {'timestamp': '2026-01-14 12:00:15', 'user': 'admin', 'src_ip': '10.0.0.2', 'status': 'FAIL'},
        {'timestamp': '2026-01-14 12:00:30', 'user': 'admin', 'src_ip': '10.0.0.3', 'status': 'FAIL'},
        {'timestamp': '2026-01-14 12:00:45', 'user': 'admin', 'src_ip': '10.0.0.4', 'status': 'FAIL'},
    ]
    
    print("\n[STEP 1] Ingesting brute force logs...")
    for log in logs:
        event = parse_auth_log(log)
        insert_event(event)
    print(f"[+] {len(logs)} events ingested (4 unique source IPs)")
    
    # Correlate
    print("\n[STEP 2] Correlating events...")
    events = fetch_events()
    incidents = correlate_events(events)
    print(f"[+] {len(incidents)} incident(s) detected")
    
    if not incidents:
        print("[-] No incidents. Exiting.")
        return
    
    incident = incidents[0]
    
    # Enrich
    print("\n[STEP 3] Enriching with threat attribution...")
    enriched = build_enriched_incident(incident, events)
    
    # Display summary
    print("\n" + "=" * 70)
    print("ENRICHED INCIDENT SUMMARY (Automated Attack)")
    print("=" * 70)
    print(f"\nEntity: {enriched['entity']}")
    print(f"Pattern: {enriched['pattern']}")
    print(f"Event Count: {enriched['event_count']}")
    print(f"Confidence: {int(enriched['confidence'] * 100)}%")
    print(f"Severity: {enriched['severity']}")
    print(f"\nMITRE Technique: {enriched['mitre']['technique_id']} - {enriched['mitre']['technique_name']}")
    print(f"Tactic: {enriched['mitre']['tactic']}")
    print(f"\nThreat Attribution: {enriched['attribution']}")
    print(f"\nNote: {enriched['event_count']} source IPs detected → heuristic identified as automated/botnet")


if __name__ == "__main__":
    initialize_db()
    test_credential_compromise_enrichment()
    test_brute_force_enrichment()
    print("\n[+] Day 4 tests complete\n")
