# ingestion/schemas.py
from dataclasses import dataclass
from typing import Dict, Any
from datetime import datetime


@dataclass
class NormalizedEvent:
    timestamp: datetime
    source: str            # auth / network / endpoint
    event_type: str        # login_failed, login_success, process_exec, file_access, etc.
    entity: str            # user / ip / host
    severity: int          # 1–10
    metadata: Dict[str, Any]

