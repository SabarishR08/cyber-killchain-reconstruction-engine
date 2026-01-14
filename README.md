# Cyber Kill Chain Reconstruction Engine

## Problem Statement

Security teams process millions of log events daily. Correlating these into coherent attack narratives is manual, error-prone, and slow. This engine automates incident reconstruction by normalizing raw logs, correlating events into patterns, reconstructing attacks as directed graphs, and enriching incidents with MITRE ATT&CK mappings and threat actor attribution.

## How It Works

### Core Pipeline

```
Raw Logs → Ingestion → Normalized Schema → Correlation → Incidents
                ↓            ↓                    ↓           ↓
          (validation)   (timestamp,         (time-window)  (pattern)
                         source,               (3+ failed    (rules-based
                         event_type,           logins =      detection)
                         entity,               brute force)
                         severity,
                         metadata)
                                                   ↓
                                    ┌──────────────┼──────────────┐
                                    ↓              ↓              ↓
                                Kill Chain      Graph          Timeline
                                (MITRE ATT&CK)  (networkx)     (sorted)
                                    ↓              ↓              ↓
                        Attribution + Risk Score + Analyst Report
```

### Key Components

**Ingestion** (`ingestion/log_parser.py`)
- Parses raw event dicts with validation (required fields: timestamp, user, src_ip, status)
- Multiple timestamp format support (ISO 8601, custom)
- Graceful error handling with descriptive exceptions

**Correlation Engine** (`correlation/correlator.py` + `rules.py`)
- Time-window aggregation (default: 10 minutes)
- Pattern-based detection: brute force (3+ failed logins), credential compromise (failed→success)
- Configuration-driven thresholds in `CORRELATION_CONFIG`
- No ML—pure deterministic logic

**Kill Chain Mapping** (`killchain/stages.py`, `mitre_mapping.py`)
- Maps incident patterns to Lockheed Martin 7-stage model
- MITRE ATT&CK enrichment: Brute force → T1110, Valid Account misuse → T1078
- Structured incident object with technique IDs and confidence scores

**Graph & Timeline** (`graph/attack_graph.py`, `reporting/timeline.py`)
- Directed networkx graphs showing entity relationships and attack flow
- Chronologically sorted event sequences with full metadata preservation

**Threat Attribution** (`reporting/attribution.py`)
- Behavioral heuristics: Multi-source (4+ IPs) → "automated/botnet"; single-source credential hunting → "targeted attack"
- Confidence scoring based on pattern repetition and time clustering
- Human-readable incident narratives

**Risk Scoring** (`reporting/scoring.py`)
- 0-100 scale: Severity (40 points) + Confidence (40 points) + MITRE weight (20 points)
- Priority labels: CRITICAL (90+), HIGH (70-89), MEDIUM (40-69), LOW (<40)
- Operationalizes SOC triage workflows

## Why Non-Trivial

1. **Deterministic Design**: Time-window correlation produces repeatable, debuggable results—explainable logic, no probabilistic ML
2. **Standards Grounded**: MITRE ATT&CK and Lockheed Martin kill chain mappings make output actionable to security teams
3. **Production-Oriented**: Input validation, error recovery, idempotent DB operations, deterministic ordering, audit logging
4. **Modular Pipeline**: Clear separation (ingestion → correlation → enrichment → reporting) enables independent testing and evolution
5. **Minimal Dependencies**: Uses stdlib (dataclasses, datetime, json, sqlite3) + pandas, networkx only—no framework bloat

## Quick Start

### Setup

```bash
python -m venv venv
source venv/Scripts/activate  # Windows: venv\Scripts\activate
pip install pandas networkx fastapi uvicorn
```

### Run Pipeline

```bash
# Full pipeline: ingest + analyze + report
python main.py --ingest data/sample_logs.json --analyze --report

# Ingest only
python main.py --ingest data/sample_logs.json

# Analyze (correlate stored events)
python main.py --analyze

# Generate report
python main.py --report
```

### Log Format

JSON dicts with required fields:

```json
{
  "timestamp": "2026-01-14 10:15:02",
  "user": "alice",
  "src_ip": "192.168.1.10",
  "status": "FAIL"
}
```

- **status**: `FAIL` (severity 6) or `SUCCESS` (severity 3)
- **timestamp**: ISO 8601 or `YYYY-MM-DD HH:MM:SS`

### Sample Output

```json
{
  "incident_id": "incident_001",
  "pattern_type": "credential_compromise",
  "severity": "HIGH",
  "risk_score": 92,
  "priority": "CRITICAL",
  "mitre_techniques": [
    {
      "technique_id": "T1078",
      "technique_name": "Valid Accounts"
    }
  ],
  "threat_actor": "likely_targeted_credential_attack",
  "confidence": 1.0,
  "explanation": "User alice experienced credential compromise: failed login attempts from 192.168.1.50 followed by successful access.",
  "timeline": [
    ["2026-01-14T10:15:02", "alice", "login_failed"],
    ["2026-01-14T10:15:15", "alice", "login_success"]
  ]
}
```

## Configuration

Adjust detection parameters in `correlation/rules.py`:

```python
CORRELATION_CONFIG = {
    "brute_force_threshold": 3,
    "credential_compromise_threshold": 2,
    "time_window_minutes": 10,
    "confidence_weights": {
        "brute_force": 0.8,
        "credential_compromise": 1.0
    }
}
```

## Testing

```bash
python test_day2.py   # Correlation patterns
python test_day3.py   # Graphs and timelines
python test_day4.py   # MITRE and attribution
```

## Operational Guarantees

- **Deterministic**: Same input → same output (no randomness, fully reproducible)
- **Traceable**: Every incident includes source events, detection rationale, and confidence scoring
- **Idempotent**: Re-ingesting same event doesn't duplicate incidents; safe for replay
- **Robust**: Invalid inputs handled gracefully; valid events process with full error recovery
- **Extensible**: New log sources, patterns, and enrichments integrate without core changes

## Project Structure

```
cyber-killchain-reconstruction-engine/
├── ingestion/
│   ├── log_parser.py      # Parsing and validation
│   └── schemas.py         # NormalizedEvent dataclass
├── datastore/
│   ├── db.py              # SQLite interface
│   └── models.py          # Event insertion
├── correlation/
│   ├── correlator.py      # Time-window aggregation
│   └── rules.py           # Pattern detection
├── killchain/
│   ├── stages.py          # Kill chain enum
│   └── mitre_mapping.py   # MITRE ATT&CK mapping
├── graph/
│   └── attack_graph.py    # networkx graph construction
├── reporting/
│   ├── timeline.py        # Event chronology
│   ├── attribution.py     # Threat actor inference
│   └── scoring.py         # Risk calculation
├── data/sample_logs/      # Test data
├── main.py                # Entry point
└── README.md
```

## Future Work

- REST API for streaming incidents
- Additional log sources (firewall, endpoint, DNS)
- Custom rule DSL for SOC teams
- Incident deduplication
- Playbook trigger automation
