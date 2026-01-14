# datastore/models.py
import json
from datastore.db import get_connection
from ingestion.schemas import NormalizedEvent
from typing import Optional


def insert_event(event: NormalizedEvent) -> Optional[int]:
    """
    Insert normalized event into database.
    
    Args:
        event: NormalizedEvent to insert
        
    Returns:
        Event ID if successful, None if failed
        
    Raises:
        ValueError: If event validation fails
        TypeError: If event type is invalid
    """
    if not isinstance(event, NormalizedEvent):
        raise TypeError(f"Expected NormalizedEvent, got {type(event)}")
    
    if not event.timestamp or not event.entity:
        raise ValueError("Event must have timestamp and entity")
    
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO events (timestamp, source, event_type, entity, severity, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            event.timestamp.isoformat(),
            event.source or "unknown",
            event.event_type or "unknown",
            event.entity,
            event.severity,
            json.dumps(event.metadata or {})
        ))

        conn.commit()
        event_id = cursor.lastrowid
        conn.close()
        
        return event_id
    except Exception as e:
        raise RuntimeError(f"Failed to insert event: {e}") from e
