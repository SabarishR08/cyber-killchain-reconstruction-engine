# Cyber Kill Chain Reconstruction Engine

A deterministic, rule-driven system for reconstructing attack narratives from raw security logs. Designed for SOC/DFIR teams requiring explainable incident correlation without probabilistic ML.

## Problem Statement

SOC teams process millions of log events daily from diverse sources. Identifying coherent attack narratives requires:

- **Normalization**: Convert diverse log formats into uniform schema.
- **Correlation**: Detect multi-event patterns (e.g., repeated failed logins followed by successful access).
- **Enrichment**: Map incidents to MITRE ATT&CK and Lockheed Martin kill chain stages.
- **Attribution**: Infer attacker behavior from observable evidence.
- **Prioritization**: Rank incidents by risk and business impact.

Manual correlation is error-prone and slow. This system automates the workflow while ensuring full explainability of detection logic.

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
- **Patterns detected**:
  - **Brute force**: 3+ failed login attempts on same account
  - **Credential compromise**: Failed login(s) followed by success
- **Configuration-driven**: Thresholds in `CORRELATION_CONFIG`; no hardcoded values
- **Deterministic**: Identical output for same input; no randomness or sampling

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

**Deterministic**: Identical output for identical input. No randomness or sampling. Enables repeatability, debugging, and forensic auditability.

**Explainable**: Rule-based logic only. No ML black boxes. Analysts understand why incidents are detected.

**Standards-based**: Uses MITRE ATT&CK and Lockheed Martin kill chain. Output integrates with SOC and threat intelligence workflows.

**Configuration-driven**: Detection thresholds in YAML and environment variables. Tune per environment without code changes.

**Modular**: Clear separation (ingestion → correlation → enrichment → reporting). Components are independently testable and can evolve without refactoring.

**Minimal dependencies**: Python stdlib plus pandas and networkx only. Reduces attack surface and deployment complexity.

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

## Testing and CI/CD

### Unit Tests (41 total, 100% passing)

```bash
# Run all tests
python -m pytest test_ingestion.py test_correlation.py test_killchain.py test_reporting.py -v

# Run specific module
python -m pytest test_ingestion.py -v

# With coverage report
python -m pytest --cov=. --cov-report=html
```

| Module | Tests | Coverage |
|--------|-------|----------|
| `ingestion/log_parser.py` | 8 | Timestamp parsing, field validation, error handling |
| `correlation/` | 9 | Brute force detection, credential compromise patterns |
| `killchain/` | 9 | Kill chain mapping, MITRE enrichment |
| `reporting/` | 15 | Risk scoring, prioritization, attribution |

### CI/CD Pipeline

GitHub Actions (`ci.yml`):
- **Test job**: Python 3.8–3.11 on Windows, Linux, macOS; Flake8 linting; coverage reporting
- **Security job**: Bandit (static analysis), Safety (dependency scanning)
- **Integration job**: End-to-end pipeline validation

Triggered on push/PR to main or develop branches.

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

- **Deterministic**: Identical output for identical input. No randomness.
- **Traceable**: Every incident includes source events, rationale, and confidence. Correlation IDs link related log entries.
- **Idempotent**: Duplicate events do not create duplicate incidents. Safe for replay.
- **Error handling**: Invalid inputs rejected with descriptive errors. Valid events process successfully.
- **Extensible**: New sources, rules, and enrichment integrate with minimal core changes.

## Known Limitations

- **Detection scope**: Detects brute force and credential compromise only. No lateral movement, exfiltration, or anomaly detection.
- **Correlation window**: Fixed time-window approach; cannot detect slow attacks spanning hours/days with sparse events.
- **Attribution**: Rule-based heuristics, not behavioral ML. May miss novel attack patterns.
- **Scalability**: SQLite suitable for ~100K events/day. Larger deployments need PostgreSQL migration.
- **Real-time**: Batch-only. Real-time streaming requires message queue integration.

## Future Enhancements

**High Priority**
- Real-time streaming (Kafka, message queues)
- REST API for incident query
- Additional log sources (firewall, DNS, endpoint, Windows Event Log)
- Incident deduplication

**Medium Priority**
- Custom detection rule DSL
- Playbook automation
- Prometheus metrics export
- Kubernetes deployment manifests

**Lower Priority**
- Graph-based anomaly detection
- Threat intelligence feed integration
- Attack graph visualization UI
- Multi-tenancy support
- Compliance reporting (SOC 2, FedRAMP)

## Summary

The Cyber Kill Chain Reconstruction Engine automates incident correlation and enrichment with deterministic, explainable logic. Appropriate for SOC teams requiring rule-based detection without ML black boxes. Current implementation covers core attack patterns (brute force, credential compromise) with full testing, logging, and configuration support. Modular architecture enables extension to additional patterns and sources.
