# Automated PCAP Forensic Analysis Tool

> An automated PCAP/PCAPNG forensic analysis tool developed in Python for Digital Forensics & Incident Response (DFIR) and Network Security.

> **Project Status:** 🚧 In Development

---

## Overview

This project automatically analyzes `.pcap` and `.pcapng` files and generates a forensic report containing network statistics, threat detection results, threat intelligence enrichment, and risk assessment.

The primary goal of this project is to improve my Python, DFIR, and software engineering skills while building a production-oriented portfolio project.

This repository is still under active development.

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
    - URLHaus
- HTML report generation
- Risk scoring
- Unit testing with Pytest

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

```
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
```

---

## Development Status

### Completed

- Parser
- Statistics Engine
- Threat Detection
- Threat Intelligence
- HTML Reporter

### In Progress

- Threat Intelligence Tests
- Additional Detection Rules
- JSON Export
- CSV Export
- PDF Export

---

## Testing

Current Status

- 79 / 79 tests passing

Current Coverage

- Overall Coverage: 66%
- Threat Intelligence tests are currently under development.

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

---

## AI Assistance

This project is primarily developed by me as a learning and portfolio project.

During development, AI tools (including ChatGPT) are used for learning Python concepts, reviewing architecture, discussing implementation approaches, improving code quality, and generating documentation.

Every implementation is reviewed, tested, and integrated manually before becoming part of the project.

---

## License

MIT License