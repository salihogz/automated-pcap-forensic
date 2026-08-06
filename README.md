# Automated PCAP Forensic Analysis Tool

> An automated PCAP/PCAPNG forensic analysis tool developed in Python for Digital Forensics & Incident Response (DFIR) and Network Security.

> **Project Status:** ✅ Production-Ready (Core Features Completed)

---

## Overview

This project automatically analyzes `.pcap` and `.pcapng` files and generates a forensic report containing network statistics, threat detection results, threat intelligence enrichment, and risk assessment.

The primary goal of this project is to improve my Python, DFIR, and software engineering skills while building a production-oriented portfolio project.

The core functionality of the project has been completed and is fully operational. Future development will focus on adding new detection techniques, export formats, and feature enhancements while preserving the existing architecture.

---

## Installation

Requires **Python 3.14**.

```bash
git clone https://github.com/salihogz/automated-pcap-forensic.git
cd automated-pcap-forensic

python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -r requirements.txt                       # runtime only
pip install -r requirements.txt -r requirements-dev.txt   # + tests & linting
```

### API keys (optional)

Threat intelligence enrichment reads its keys from a `.env` file in the project root. A provider with no key configured is **skipped**, not treated as an error — the tool runs fine with no `.env` at all, it just won't enrich IPs.

```dotenv
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
OTX_API_KEY=your_otx_key
```

---

## Usage

```bash
# Analyze a specific capture
python main.py -f samples/malicious/capture.pcapng

# No -f: the first capture found under samples/ (searched recursively) is used
python main.py

# DEBUG-level logging
python main.py -v
```

| Flag | Description |
| --- | --- |
| `-f`, `--file` | Path to the PCAP/PCAPNG file to analyze |
| `-v`, `--verbose` | Enable DEBUG-level logging |

The HTML report is written to `reports/<clean|malicious>/<capture-name>_report.html`. The subfolder is derived from the capture's parent directory name (`samples/malicious/x.pcapng` → `reports/malicious/x_report.html`); anything else falls back to `clean/`.

The report is fully self-contained — charts are embedded as base64, so it has **no external references** and can be opened offline on an air-gapped forensic workstation.

Capture files under `samples/` are gitignored; only `.gitkeep` is tracked, so a fresh checkout contains no sample captures.

---

## Current Features

- PCAP / PCAPNG parsing
- Streaming packet processing (memory-friendly on large captures)
- General traffic statistics
- Protocol statistics
- Rule-based threat detection (8 rules, see below)
- Threat Intelligence enrichment
    - VirusTotal
    - AbuseIPDB
    - AlienVault OTX
- HTML report generation
- Risk scoring
- Environment-based API configuration (.env)
- Comprehensive error handling
- Unit testing with Pytest
- Static analysis with Ruff

### Detection Rules

| Rule ID | Detects |
| --- | --- |
| `SEC-PORT-SCAN-001` | Many distinct destination ports contacted within a time window |
| `SEC-SYN-SCAN-001` | TCP SYN scanning at the flag level |
| `SEC-ICMP-FLOOD-001` | ICMP flooding |
| `SEC-FAILED-TCP-001` | Bursts of failed TCP connection attempts |
| `SEC-DNS-TUNNEL-001` | DNS tunneling (query volume/entropy per base domain) |
| `SEC-LONG-DOMAIN-001` | Abnormally long domain names |
| `SEC-DGA-001` | Algorithmically generated (DGA) domain names |
| `SEC-EXFIL-001` | Large outbound data transfers to public IPs |

All thresholds and time windows are defined in `config.py`, which is the single source of truth for tunable values.

---

## Technology Stack

**Runtime:** Python 3.14 · Scapy · Requests · urllib3 · Matplotlib · Jinja2 · python-dotenv

**Development:** Pytest · pytest-cov · BeautifulSoup4 (report DOM assertions) · Ruff

---

## Project Structure

```
Automated-PCAP-Forensic/
├── modules/                 # parser, statistics, threat_detector, threat_intel, reporter, models
├── templates/               # report.html.j2 (Jinja2 view layer)
├── tests/                   # pytest suite + snapshots/
├── reports/                 # generated HTML reports (gitignored)
├── samples/                 # clean/ and malicious/ capture files (gitignored)
├── static/
├── logs/                    # analysis.log (gitignored)
├── config.py                # thresholds, windows, paths, API config
├── main.py                  # CLI entry point / pipeline orchestration
├── requirements.txt         # runtime dependencies
├── requirements-dev.txt     # test & lint dependencies
└── README.md
```

---

## Architecture

The pipeline is orchestrated by `main.py` and is single-pass / streaming wherever possible:

```
PCAPParser.parse()           →  list[PacketInfo]
build_general_statistics()   →  GeneralStatistics
ThreatDetector.detect()      →  list[ThreatFinding]
ThreatIntelService.enrich()  →  dict[str, list[NormalizedIOCResult]]   (parallel, public IPs only)
Reporter.generate()          →  reports/<clean|malicious>/<name>_report.html
```

Data contracts live in `modules/models.py` and are shared across every stage. `PacketInfo` and `ThreatFinding` are frozen dataclasses — treated as immutable for chain-of-custody/data-integrity reasons.

---

## Development Status

### Completed

- Parser
- Statistics Engine
- Threat Detection
- Threat Intelligence
- HTML Reporter
- Threat Intelligence Test Suite
- Environment-based Configuration
- Comprehensive Error Handling

### Planned

- Additional Detection Rules
- JSON Export
- CSV Export
- PDF Export
- Docker Support

---

## Testing

```bash
pytest                                              # full suite
pytest tests/test_parser.py                         # single file
pytest tests/test_parser.py::test_name -v           # single test
pytest --cov=modules --cov=main --cov-report=html   # coverage → htmlcov/
ruff check .                                        # lint
ruff format .                                       # format
```

**Current status:** 137 / 137 tests passing · 89% coverage across `modules/`

| Module | Coverage |
| --- | --- |
| `modules/statistics.py` | 99% |
| `modules/threat_detector.py` | 95% |
| `modules/models.py` | 93% |
| `modules/reporter.py` | 88% |
| `modules/threat_intel.py` | 87% |
| `modules/parser.py` | 77% |

`main.py` is currently covered only indirectly and is a known gap in the test suite.

---

## Development Principles

This project follows:

- SOLID Principles
- Streaming Architecture
- Memory Friendly Processing
- Fail-Fast Error Handling
- Type Hints
- Dataclasses
- Modular Design
- Production-oriented project structure
- Environment-based configuration
- Backward compatibility whenever possible

---

## Development Process

This project is developed as a hands-on learning and portfolio project with a strong focus on software engineering best practices.

External development tools may be used for research, architecture discussions, documentation, and code review. All design decisions, implementations, testing, and final integration are performed manually before becoming part of the project.

---

## License

MIT License
