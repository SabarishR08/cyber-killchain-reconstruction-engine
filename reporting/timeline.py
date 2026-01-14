# reporting/timeline.py
from typing import List, Dict, Any
from ingestion.schemas import NormalizedEvent


def build_timeline(events: List[NormalizedEvent]) -> List[Dict[str, Any]]:
    """
    Build chronological timeline from events.
    Returns list of timeline entries sorted by timestamp.
    """
    return sorted(
        [
            {
                "time": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "entity": e.entity,
                "source": e.source,
                "severity": e.severity,
                "metadata": e.metadata
            }
            for e in events
        ],
        key=lambda x: x["time"]
    )


def print_timeline(events: List[NormalizedEvent], title: str = ""):
    """Pretty print incident timeline."""
    if title:
        print(f"\n[TIMELINE] {title}")
        print("=" * 60)
    
    timeline = build_timeline(events)
    
    for i, entry in enumerate(timeline, 1):
        print(f"{i}. [{entry['time']}] {entry['event_type'].upper()}")
        print(f"   Entity: {entry['entity']}")
        print(f"   Source: {entry['source']} | Severity: {entry['severity']}")
        if entry['metadata']:
            for key, value in entry['metadata'].items():
                print(f"   {key}: {value}")
        print()


def get_timeline_stats(events: List[NormalizedEvent]) -> Dict[str, Any]:
    """Get timeline statistics."""
    if not events:
        return {}
    
    timeline = build_timeline(events)
    
    # Count events by type
    event_counts = {}
    for entry in timeline:
        event_type = entry['event_type']
        event_counts[event_type] = event_counts.get(event_type, 0) + 1
    
    # Time span
    if timeline:
        start = timeline[0]['time']
        end = timeline[-1]['time']
    else:
        start = end = None
    
    return {
        'total_events': len(timeline),
        'event_types': event_counts,
        'start_time': start,
        'end_time': end,
    }
