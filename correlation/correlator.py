# correlation/correlator.py
from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Any
from ingestion.schemas import NormalizedEvent
from correlation.rules import is_bruteforce, is_credential_compromise


TIME_WINDOW = timedelta(minutes=10)


def correlate_events(events: List[NormalizedEvent]) -> List[Dict[str, Any]]:
    """Group events by entity and time window, detect patterns."""
    incidents = []

    # Group events by entity
    events_by_entity = defaultdict(list)
    for event in events:
        events_by_entity[event.entity].append(event)

    # Process each entity's events
    for entity, entity_events in events_by_entity.items():
        # Sort by timestamp
        entity_events.sort(key=lambda e: e.timestamp)

        # Slide through time window
        window = []
        for event in entity_events:
            if not window:
                window.append(event)
                continue

            # If event is within time window of first event
            if event.timestamp - window[0].timestamp <= TIME_WINDOW:
                window.append(event)
            else:
                # Analyze completed window
                incident = analyze_window(window)
                if incident:
                    incidents.append(incident)
                window = [event]

        # Analyze final window
        if window:
            incident = analyze_window(window)
            if incident:
                incidents.append(incident)

    return incidents


def analyze_window(events: List[NormalizedEvent]) -> Dict[str, Any]:
    """Analyze a time window of events for attack patterns."""
    if not events:
        return None

    # Check for brute force
    if is_bruteforce(events):
        return {
            "entity": events[0].entity,
            "pattern": "Brute Force Authentication Attempt",
            "kill_chain_stage": "Initial Access",
            "event_count": len(events),
            "events": events
        }

    # Check for credential compromise
    if is_credential_compromise(events):
        return {
            "entity": events[0].entity,
            "pattern": "Possible Credential Compromise",
            "kill_chain_stage": "Initial Access",
            "event_count": len(events),
            "events": events
        }

    return None
