# Project Summary: Cyber Kill Chain Reconstruction Engine

## Overview

This document describes the system architecture, design decisions, implementation status, and known limitations of the Cyber Kill Chain Reconstruction Engine.

## System Capabilities

### Core Functionality

| Capability | Status | Details |
|------------|--------|---------|
| Log ingestion and validation | Complete | Parses JSON logs; validates required fields; supports multiple timestamp formats |
| Event correlation | Complete | Time-window pattern detection; detects brute force and credential compromise |
| Kill chain mapping | Complete | Maps incidents to Lockheed Martin 7-stage model |
| MITRE ATT&CK enrichment | Complete | Adds technique IDs (T1110, T1078, etc.) to incidents |
| Attack graph construction | Complete | Builds directed graphs of entity relationships |
| Timeline reconstruction | Complete | Chronologically sorts events with full metadata |
| Threat actor attribution | Complete | Behavioral heuristics for attacker classification |
| Risk scoring | Complete | 0-100 scale with priority labels (CRITICAL/HIGH/MEDIUM/LOW) |
| Configuration management | Complete | YAML file + environment variable overrides |
| Structured logging | Complete | Dual-channel logging with correlation IDs |
| Automated testing | Complete | 41 unit tests with 100% pass rate |
| CI/CD pipeline | Complete | GitHub Actions with multi-platform testing |

### Detected Attack Patterns

1. **Brute Force**: 3+ failed login attempts on same account within configurable time window
2. **Credential Compromise**: Failed login(s) followed by successful login on same account within window

## Architecture and Design Decisions

### Design Philosophy

**Deterministic over probabilistic**: All detection logic uses explicit rules and thresholds. No ML models, learned parameters, or sampling. This enables:
- Reproducibility: Same input always produces same output
- Auditability: Clear rationale for every detection
- Debuggability: Can trace through logic step-by-step
- Defensibility: No black-box decisions for compliance/legal contexts

**Configuration-driven over hardcoded**: All tunable parameters (time windows, thresholds, weights) stored in external `config.yaml` and environment variables. Enables:
- Environment-specific tuning without code changes
- Easy A/B testing of detection sensitivity
- Operational flexibility for SOC teams

**Modular over monolithic**: Clear separation of ingestion, correlation, enrichment, and reporting. Enables:
- Independent testing of each component
- Incremental improvements without system-wide refactoring
- Easy addition of new detection rules and enrichment sources

**Standards-based over proprietary**: Uses MITRE ATT&CK and Lockheed Martin kill chain. Enables:
- Integration with threat intelligence platforms
- Compatibility with SOC/SIEM tools
- Alignment with industry incident classification

### Component Design

**Ingestion** (`ingestion/log_parser.py`)
- Design: Minimal schema (timestamp, user, src_ip, status) + arbitrary metadata preservation
- Rationale: Reduces required data normalization upstream; extensible for new log sources
- Validation: Required fields enforced; graceful error handling for invalid records
- Timestamp formats: ISO 8601 + YYYY-MM-DD HH:MM:SS; extensible via TIMESTAMP_FORMATS list

**Correlation** (`correlation/correlator.py`, `rules.py`)
- Design: Fixed time-window (default 10 min) with event counting
- Rationale: Simple, deterministic, computationally efficient
- Patterns: Configurable thresholds in CORRELATION_CONFIG dict
- Output: Incident objects with constituent events and confidence scores

**Kill Chain & MITRE** (`killchain/stages.py`, `mitre_mapping.py`)
- Design: Hardcoded mappings from pattern type to kill chain stage and MITRE technique
- Rationale: Pattern detection is the hard problem; mapping is straightforward lookup
- Extensibility: Add new patterns to correlation engine; then add mappings here
- Confidence: Based on pattern certainty, not independent scoring

**Attack Graph** (`graph/attack_graph.py`)
- Design: Directed networkx graph with entities (nodes) and interactions (edges)
- Rationale: Standard graph library enables analysis (path traversal, centrality, etc.) and visualization
- Nodes: User, IP address, host (extensible)
- Edges: Login attempt, lateral movement candidate, etc.

**Attribution** (`reporting/attribution.py`)
- Design: Behavioral heuristics based on observable patterns (source count, timing)
- Rationale: Avoids ML/learning; interpretable to analysts
- Patterns: Multi-source (suggests automated tool), single-source (suggests targeted), time clustering
- Output: Human-readable attacker classification with confidence

**Risk Scoring** (`reporting/scoring.py`)
- Design: Component-based score (severity + confidence + MITRE weight)
- Rationale: Enables SOC triage; each component independently tunable
- Severity: Event type classification (0-40 points)
- Confidence: Pattern certainty (0-40 points)
- MITRE weight: Technique criticality (0-20 points)
- Priority labels: Thresholds configurable in config.yaml

### Data Persistence

**Database**: SQLite with idempotent insert operations
- Design rationale: Simple, serverless, suitable for log volumes up to ~100K/day
- Idempotency: Events deduplicated by (timestamp, user, src_ip, status) tuple
- Migration path: Can export to PostgreSQL for larger scales

## Implementation Status

### Components Implemented

| Component | Files | Status | Tests |
|-----------|-------|--------|-------|
| Ingestion | ingestion/ (2 files) | Complete | 8 tests |
| Correlation | correlation/ (2 files) | Complete | 9 tests |
| Kill Chain | killchain/ (2 files) | Complete | 9 tests |
| Graph | graph/ (1 file) | Complete | (covered in integration) |
| Reporting | reporting/ (3 files) | Complete | 15 tests |
| Configuration | config.py, config.yaml | Complete | (covered in integration) |
| Logging | logger.py | Complete | (covered in integration) |
| CLI | main.py | Complete | (tested manually) |

### Test Coverage

- **Total tests**: 41 (100% passing)
- **Test framework**: pytest
- **Coverage areas**:
  - Ingestion: Timestamp parsing, field validation, error handling, metadata preservation
  - Correlation: Brute force detection, credential compromise, time-window boundaries
  - Kill Chain: Stage mapping, MITRE enrichment, incident construction
  - Reporting: Risk scoring (0-100), priority labeling, timeline generation, threat attribution
- **Integration testing**: Full pipeline validated with sample data (2 incidents detected correctly)

### CI/CD Pipeline

- **Platform**: GitHub Actions
- **Test matrix**: Python 3.8-3.11, Windows/Linux/macOS
- **Jobs**:
  - Test: pytest + coverage reporting
  - Security: Bandit (static analysis) + Safety (dependency checking)
  - Integration: End-to-end pipeline validation
- **Triggers**: Push/PR to main or develop branches

## Design Decisions and Tradeoffs

| Decision | Rationale | Tradeoff |
|----------|-----------|----------|
| Deterministic rules over ML | Explainability, reproducibility, auditability | May miss novel attack patterns |
| Fixed time-window correlation | Simplicity, determinism, efficiency | Cannot detect attacks spanning hours/days with sparse events |
| SQLite backend | No external dependencies, simple deployment | Not suitable for >100K events/day; requires migration for scale |
| Behavioral heuristics for attribution | Interpretable, rule-based | May not capture sophisticated attacker variations |
| Hardcoded kill chain mappings | Clear, maintainable, not a performance bottleneck | Requires code change to add new pattern types |
| Batch processing | Simplified logic, easier testing | Not suitable for real-time SOC dashboards |
| Minimal dependencies | Reduced attack surface, easier deployment | Limited pre-built functionality (e.g., no API framework included) |

## Known Limitations

### Detection Scope

The system currently detects two attack patterns:
1. **Brute force**: Failed login attempts
2. **Credential compromise**: Failed→successful login sequence

It does NOT detect:
- Lateral movement (host-to-host connections)
- Data exfiltration (large data transfers)
- Resource consumption anomalies (CPU, memory, disk)
- Web application attacks (SQL injection, XSS, etc.)
- Network-level attacks (DDoS, port scans)

### Correlation Window

Uses fixed time-window approach (default 10 minutes). Cannot detect:
- Multi-day attacks with sparse events
- Slow-and-low reconnaissance (hours between events)
- Time-zone spanning attacks where timing is key

### Behavioral Attribution

Confidence scores are rule-based, not learned. May misclassify:
- Legitimate users with unusual patterns (new role, location change)
- Sophisticated APT using varied tactics
- Insider threats with slow, deliberate actions

### Scalability

SQLite backend becomes a bottleneck above ~100K events/day due to:
- Locking overhead (single writer)
- No partitioning or sharding
- Memory requirements for large datasets

### Real-time Processing

Current architecture is batch-oriented. To support real-time:
- Would need message queue (Kafka, RabbitMQ)
- State machine for correlating incomplete patterns
- Streaming aggregation logic (different from batch)
- Complex deployment (multiple services)

### Log Source Coverage

Currently assumes login/auth logs. To support other sources:
- Firewall logs: Requires different schema and correlation logic
- DNS logs: Requires DNS-specific pattern detection
- Endpoint logs: Requires process/network relationship modeling
- Cloud logs (AWS CloudTrail, Azure Activity): Requires cloud-specific parsing

## Quality Metrics

| Metric | Value |
|--------|-------|
| Unit tests | 41/41 passing (100%) |
| Code files | 15 (core implementation) |
| Test files | 8 |
| Configuration parameters | 25+ (tunable via YAML/env) |
| Log channels | 2 (main + audit) |
| CI/CD platforms | 3 (Windows, Linux, macOS) |
| Python versions | 4 (3.8, 3.9, 3.10, 3.11) |
| Lines of code | ~2000 (core) |
| Documentation | Comprehensive README + this summary |

## Dependencies

### Python Packages

| Package | Purpose | Version |
|---------|---------|---------|
| pandas | Data manipulation, time-window aggregation | 1.x+ |
| networkx | Graph construction and analysis | 2.x+ |
| pyyaml | Configuration parsing | 5.x+ |
| pytest | Unit testing | 6.x+ |
| pytest-cov | Coverage reporting | 2.x+ |
| python-dateutil | Timestamp parsing flexibility | 2.x+ |

### No External Dependencies For

- SQLite (stdlib)
- HTTP/API (not implemented)
- Message queues (batch-only for now)
- ML/Statistics (deterministic rules only)

## Deployment Considerations

### System Requirements

- **Python**: 3.8+
- **OS**: Windows, Linux, macOS
- **Disk**: ~1 GB for 100K events (SQLite)
- **Memory**: ~256 MB base, +5 MB per 10K events
- **CPU**: Minimal; correlation is O(n log n) where n = events in window

### Production Deployment

To deploy in production SOC environment:

1. **Environment configuration**: Tuning via config.yaml and KILLCHAIN_* variables for your log volumes and SLA
2. **Log ingestion**: Integrate with your log aggregation (syslog, rsyslog, Splunk forwarder, etc.)
3. **Output routing**: Send incidents to your ticketing system (ServiceNow, Jira) or SIEM
4. **Monitoring**: Add Prometheus metrics export for operational dashboards
5. **Scaling**: Migrate to PostgreSQL backend for >100K events/day

### Operational Checklist

- [ ] config.yaml reviewed and tuned for environment
- [ ] Log source validated (format, required fields)
- [ ] Database path writable and backed up regularly
- [ ] Log rotation and retention configured
- [ ] Incident output integrated with ticketing/SIEM
- [ ] Alerts enabled and routed to on-call
- [ ] Runbooks created for common incidents
- [ ] Change control process documented

## Future Enhancement Opportunities

### High Priority

- Real-time streaming (Kafka integration, streaming aggregation)
- REST API for incident query and export
- Additional log sources (Windows Event Log, firewall, DNS, endpoint)
- Incident deduplication and rollup (suppress duplicates in burst scenarios)

### Medium Priority

- Custom detection rule DSL (enable SOC teams to write rules without code)
- Playbook automation (automated response triggers)
- Performance metrics export (Prometheus)
- Container deployment (Dockerfile, Kubernetes manifests)
- Tuning dashboard (visibility into detection sensitivity)

### Lower Priority

- Advanced behavioral analysis (graph ML for anomaly detection)
- Integration with threat intelligence feeds
- Visualization UI for attack graphs and timelines
- Multi-tenancy (support multiple organizations)
- Audit compliance reporting (SOC 2, FedRAMP)

## Conclusion

The Cyber Kill Chain Reconstruction Engine provides a deterministic, standards-based approach to incident correlation and enrichment. It is well-suited for SOC teams requiring explainable detection logic and low operational complexity. Current implementation covers fundamental attack patterns (brute force, credential compromise) with full testing, logging, and configuration support.

The modular architecture enables straightforward extension to additional patterns and log sources. Known limitations (batch processing, limited detection scope, SQLite scalability) are well-understood and have documented mitigation paths for production deployment.

For questions or contributions, refer to the main README.md for architecture details and running instructions.
