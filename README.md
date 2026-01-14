# Cyber Kill Chain Reconstruction Engine

A deterministic, rule-driven system for reconstructing attack narratives from raw security logs. Designed for SOC/DFIR teams requiring explainable incident correlation without probabilistic ML.

## Problem Statement

Security operations centers process millions of log events daily across disparate sources. Identifying coherent attack narratives from this volume requires:

- **Normalization**: Parsing diverse log formats into uniform event schemas
- **Correlation**: Detecting multi-event patterns (e.g., failed login attempts preceding unauthorized access)
- **Enrichment**: Mapping incidents to standardized frameworks (MITRE ATT&CK, Lockheed Martin kill chain)
- **Attribution**: Inferring attacker behavior based on observable patterns
- **Prioritization**: Ranking incidents by risk and business impact

Manual correlation is time-consuming, error-prone, and inconsistent. This system automates the entire workflow while maintaining full explainability of detection logic.

## System Architecture

### Data Flow

```
Raw Logs (JSON)
    ↓
Ingestion (log_parser.py)
  - Validate required fields: timestamp, user, src_ip, status
  - Support multiple timestamp formats
  - Preserve arbitrary metadata
    ↓
Normalized Event Schema
  - timestamp: ISO 8601
  - source: log origin
  - event_type: login_failed, login_success, etc.
  - entity: principal (user/account)
  - severity: numeric score
  - metadata: additional fields
    ↓
Correlation Engine (correlator.py, rules.py)
  - Time-window aggregation (default: 10 minutes)
  - Pattern matching: brute force (3+ failed logins), credential compromise
  - Configuration-driven thresholds
    ↓
Incident Detection
  - Pattern type (brute_force, credential_compromise, etc.)
  - Constituent events (source facts)
  - Confidence score
    ↓
Enrichment (killchain/, graph/)
  - Kill Chain Mapping: Lockheed Martin 7-stage model
  - MITRE ATT&CK Mapping: Technique IDs (T1110, T1078, etc.)
  - Attack Graph: Directed graph of entities and relationships
  - Event Timeline: Chronological sequence with metadata
    ↓
Attribution & Scoring (reporting/)
  - Threat actor inference (behavioral heuristics)
  - Risk score (0-100): severity + confidence + MITRE weight
  - Priority label: CRITICAL / HIGH / MEDIUM / LOW
    ↓
Output (Analyst Report)
  - Incident summary with explanation
  - Mapped techniques and kill chain stages
  - Timeline for manual verification
  - Risk score and priority for triage
```

## Core Components

### Ingestion (`ingestion/log_parser.py`)

Validates and parses raw log events into normalized schema.

- **Required fields**: timestamp, user, src_ip, status
- **Timestamp formats**: ISO 8601, YYYY-MM-DD HH:MM:SS (extensible)
- **Validation**: Rejects malformed events with descriptive errors
- **Metadata preservation**: Arbitrary fields stored in metadata dict for extensibility
- **Error handling**: Graceful skipping of invalid records; valid events process normally

### Correlation Engine (`correlation/correlator.py`, `rules.py`)

Detects multi-event patterns within configurable time windows.

- **Time-window aggregation**: Groups events by entity and time bucket (default: 10 minutes)
- **Pattern detection rules**:
  - **Brute force**: 3+ failed login attempts on same account within window
  - **Credential compromise**: Failed login(s) followed by successful login on same account within window
- **Configuration-driven**: Thresholds and rules stored in `CORRELATION_CONFIG` dict; no hardcoded magic numbers
- **Deterministic**: Same input always produces same output; no randomness or sampling

### Kill Chain & MITRE Mapping (`killchain/stages.py`, `mitre_mapping.py`)

Enriches incidents with standardized security frameworks.

- **Kill Chain Stages**: Maps incident patterns to Lockheed Martin 7-stage model (Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control, Actions on Objective)
- **MITRE ATT&CK**: Technique mapping (e.g., Brute Force → T1110, Valid Accounts → T1078)
- **Confidence scores**: Based on pattern certainty and supporting evidence
- **Structured output**: Incident objects with technique IDs, stage names, and narrative explanations

### Attack Graph (`graph/attack_graph.py`)

Constructs directed graphs of entity relationships and attack progression.

- **Nodes**: Unique entities (users, IP addresses, hosts)
- **Edges**: Directed connections representing observed interactions (login attempts, lateral movement candidates)
- **Analysis**: Graph traversal for identifying attack paths and blast radius estimation
- **Visualization support**: networkx compatible for integration with visualization tools

### Timeline (`reporting/timeline.py`)

Reconstructs chronological event sequences with full context.

- **Sorting**: Events ordered by timestamp (earliest first)
- **Metadata preservation**: All event fields included for analyst review
- **Incident context**: Links events to parent incident with pattern rationale
- **Analyst-verifiable**: Timeline data suitable for manual verification workflows

### Attribution (`reporting/attribution.py`)

Infers attacker behavior patterns based on observable evidence.

- **Behavioral heuristics**:
  - Multi-source attacks (4+ distinct IPs): Suggests automated tool or botnet
  - Single-source credential hunting: Suggests targeted attack or insider threat
  - Time clustering: Rapid succession indicates automation; sparse timing suggests manual work
- **Confidence scoring**: Based on pattern repetition and supporting evidence
- **Human-readable output**: Narrative explanations suitable for analyst handoff

### Risk Scoring (`reporting/scoring.py`)

Prioritizes incidents for triage and response.

- **Scoring components**:
  - **Severity**: 0-40 points (event classification)
  - **Confidence**: 0-40 points (pattern certainty)
  - **MITRE weight**: 0-20 points (technique criticality)
- **Priority labels**: CRITICAL (90-100), HIGH (70-89), MEDIUM (40-69), LOW (0-39)
- **Incident prioritization**: Enables SOC teams to focus on highest-impact incidents first

## Design Principles

**Deterministic**: Same input produces identical output across runs. No randomness, sampling, or probabilistic elements. Enables repeatability, debugging, and forensic auditability.

**Explainable**: All detection logic is rule-based and human-readable. No ML black boxes or learned parameters. Analysts can understand why an incident was flagged.

**Standards-based**: Uses MITRE ATT&CK and Lockheed Martin kill chain mappings. Output is immediately actionable in SOC workflows and threat intelligence systems.

**Configuration-driven**: Detection thresholds and rules stored in external YAML file and environment variables. Enables tuning for different environments without code changes.

**Modular architecture**: Clear separation of concerns (ingestion, correlation, enrichment, reporting). Components are independently testable and can be evolved without system-wide refactoring.

**Minimal dependencies**: Uses Python stdlib (dataclasses, datetime, json, sqlite3) plus pandas and networkx only. No heavyweight frameworks. Reduces attack surface and deployment complexity.

## Installation

### Dependencies

- Python 3.8+
- pandas (data manipulation)
- networkx (graph analysis)
- pyyaml (configuration parsing)
- pytest, pytest-cov (testing)

### Setup

```bash
python -m venv venv
source venv/Scripts/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Running the System

### Command-Line Interface

```bash
# Full pipeline: ingest, correlate, enrich, and generate report
python main.py --ingest data/sample_logs.json --analyze --report

# Ingest logs only
python main.py --ingest data/sample_logs.json

# Analyze (correlate and enrich already-ingested events)
python main.py --analyze

# Generate report from analyzed incidents
python main.py --report

# Display detailed help
python main.py --help
```

### Input Format

Raw logs must be JSON dicts with required fields:

```json
{
  "timestamp": "2026-01-14 10:15:02",
  "user": "alice",
  "src_ip": "192.168.1.10",
  "status": "FAIL"
}
```

- **timestamp**: ISO 8601 or YYYY-MM-DD HH:MM:SS format
- **user**: Principal identifier (username, service account, etc.)
- **src_ip**: Source IP address
- **status**: Event outcome (FAIL or SUCCESS; case-insensitive)
- **Additional fields**: Preserved in metadata dict for extensibility

### Output Format

Incidents are emitted as JSON objects:

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

### Configuration File (`config.yaml`)

Detection parameters and system settings are stored in `config.yaml`:

```yaml
correlation:
  time_window_minutes: 10           # Aggregation window for pattern detection
  brute_force_threshold: 3          # Failed logins required to trigger brute force pattern
  credential_compromise_threshold: 2  # Events required for compromise pattern

risk_scoring:
  severity_weights:
    LOW: 5
    MEDIUM: 15
    HIGH: 30
    CRITICAL: 40
  mitre_bonus: 20                   # Additional points for MITRE-mapped techniques

priority_thresholds:
  CRITICAL: 90                      # Risk score cutoff for CRITICAL priority
  HIGH: 70
  MEDIUM: 40
  LOW: 0

attribution:
  multi_source_threshold: 4         # IPs required to suggest automated tool
  time_clustering_tolerance: 300    # Seconds; events within tolerance considered grouped

logging:
  level: INFO                       # Application log level
  main_log_file: logs/killchain.log
  audit_log_file: logs/audit.log

database:
  path: events.db                   # SQLite database path
```

### Environment Variable Overrides

For dynamic configuration without file changes, use `KILLCHAIN_*` environment variables:

```bash
# Override time window to 15 minutes
KILLCHAIN_TIME_WINDOW_MINUTES=15 python main.py --analyze

# Override brute force threshold to 5 failed logins
KILLCHAIN_BRUTE_FORCE_THRESHOLD=5 python main.py --analyze

# Override database path
KILLCHAIN_DB_PATH=/var/lib/killchain/events.db python main.py
```

Environment variables take precedence over `config.yaml` values.

## Testing

### Unit Tests

The system includes 41 unit tests covering ingestion, correlation, enrichment, and reporting:

```bash
# Run all tests
python -m pytest test_ingestion.py test_correlation.py test_killchain.py test_reporting.py -v

# Run specific test module
python -m pytest test_ingestion.py -v

# Run with coverage report
python -m pytest --cov=. --cov-report=html

# Run single test class
python -m pytest test_correlation.py::TestCorrelationRules -v
```

### Test Coverage

| Module | Tests | Coverage |
|--------|-------|----------|
| `ingestion/log_parser.py` | 8 | Timestamp parsing, field validation, error handling, metadata preservation |
| `correlation/` | 9 | Brute force detection, credential compromise, time-window boundaries |
| `killchain/` | 9 | Kill chain mapping, MITRE enrichment, incident construction |
| `reporting/` | 15 | Risk scoring, priority labeling, timeline generation, threat attribution |

All tests use deterministic inputs and expected outputs; no randomness or mock objects.

## Project Structure

```
cyber-killchain-reconstruction-engine/
├── ingestion/
│   ├── log_parser.py              # Event validation and parsing
│   └── schemas.py                 # NormalizedEvent dataclass
├── datastore/
│   ├── db.py                      # SQLite initialization
│   └── models.py                  # Event persistence
├── correlation/
│   ├── correlator.py              # Time-window aggregation
│   └── rules.py                   # Pattern detection with config
├── killchain/
│   ├── stages.py                  # Kill chain stage enum
│   └── mitre_mapping.py           # MITRE ATT&CK enrichment
├── graph/
│   └── attack_graph.py            # Entity relationship graphs
├── reporting/
│   ├── timeline.py                # Event chronology
│   ├── attribution.py             # Behavioral heuristics
│   └── scoring.py                 # Risk calculation
├── data/
│   └── sample_logs/               # Test data
├── test_*.py                      # Unit tests (41 tests total)
├── .github/workflows/
│   └── ci.yml                     # GitHub Actions CI/CD
├── config.py                      # Configuration manager
├── config.yaml                    # Tunable parameters
├── logger.py                      # Structured logging
├── main.py                        # CLI entry point
├── requirements.txt               # Python dependencies
├── .gitignore                     # Git ignore rules
└── README.md                      # This file
```

## System Guarantees

**Deterministic**: Same input produces identical output across runs. No randomness or sampling.

**Traceable**: Every incident includes source events, detection rationale, and confidence scores. Correlation IDs link related log entries.

**Idempotent**: Re-ingesting duplicate events does not create duplicate incidents. Safe for replay and recovery scenarios.

**Error handling**: Invalid inputs are rejected with descriptive errors. Valid events process successfully with full error recovery.

- **Extensible**: New log sources, detection rules, and enrichment logic integrate with minimal core changes.

## Known Limitations

- **Detection scope**: Currently detects brute force and credential compromise patterns. Does not detect lateral movement, data exfiltration, or resource consumption anomalies.
- **Correlation window**: Fixed time-window approach; does not capture attacks spanning hours or days with sparse events.
- **Behavioral attribution**: Confidence scores are rule-based heuristics, not behavioral ML. May not capture novel attack patterns.
- **Scalability**: SQLite backend suitable for log volumes up to ~100K events/day. Larger deployments require database migration (PostgreSQL, etc.).
- **Real-time processing**: Current implementation batch-processes logs. Real-time streaming would require architectural changes (message queues, etc.).

## Future Work

- Real-time event streaming (Kafka, RabbitMQ integration)
- REST API for incident query and export
- Additional log sources (Windows Event Log, firewall, DNS, endpoint detection)
- Custom detection rule DSL for SOC teams
- Incident deduplication and rollup
- Playbook automation (automated response triggers)
- Performance metrics export (Prometheus)
- Container deployment (Dockerfile, Kubernetes manifests)
