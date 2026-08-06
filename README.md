Markdown

# Automated PCAP Forensic Analysis Tool

> An automated PCAP/PCAPNG forensic analysis tool developed in Python for Digital Forensics & Incident Response (DFIR) and Network Security.

> **Project Status:** ✅ Production-Ready (Core Features Completed)

---

## Overview

This project automatically analyzes `.pcap` and `.pcapng` files and generates a forensic report containing network statistics, threat detection results, threat intelligence enrichment, and risk assessment.

The primary goal of this project is to improve my Python, DFIR, and software engineering skills while building a production-oriented portfolio project.

The core functionality of the project has been completed and is fully operational. Future development will focus on adding new detection techniques, export formats, and feature enhancements while preserving the existing architecture.

---

## Current Features

- PCAP / PCAPNG parsing
- Streaming packet processing
- General traffic statistics
- Protocol statistics
- Port Scan detection
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

---

## Technology Stack

- Python 3.14
- Scapy
- PyShark
- Requests
- Pandas
- Matplotlib
- Jinja2
- BeautifulSoup4
- python-dotenv
- Pytest
- Ruff

---

## Project Structure

Automated-PCAP-Forensic/
├── modules/
├── templates/
├── tests/
├── reports/
├── samples/
├── static/
├── config.py
├── main.py
└── README.md


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

Current Status

- 134 / 134 tests passing

Current Coverage

- Overall Coverage: 93%

Quality Assurance

- Pytest
- Ruff
- High branch coverage for critical modules

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