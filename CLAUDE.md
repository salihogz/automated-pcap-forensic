# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Automated PCAP/PCAPNG forensic analysis tool (DFIR / network security). It parses a capture file, computes traffic statistics, runs a rule-based threat detection engine, enriches offending IPs against external threat-intel providers, and renders everything into a single self-contained offline HTML report. This is a portfolio/learning project (Python, DFIR, software engineering skills) built with production-oriented practices: SOLID, streaming/memory-friendly processing, fail-fast error handling, type hints, dataclasses. Many docstrings and comments in this codebase are in Turkish — match that convention when editing existing files.

## Commands

The venv at `venv/` already has all dependencies installed (Python 3.14).

```bash
# Run the tool (defaults to first file found under samples/, searched recursively)
python main.py
python main.py -f samples/malicious/some_capture.pcapng
python main.py -v                     # DEBUG-level logging

# Tests
pytest                                 # full suite
pytest tests/test_parser.py            # single file
pytest tests/test_parser.py::test_name -v   # single test
pytest --cov=modules --cov=main --cov-report=html   # coverage (writes htmlcov/)

# Lint
ruff check .
ruff format .
```

`pyproject.toml` configures ruff, pytest and coverage (it is **not** a packaging manifest — dependencies live in `requirements.txt` / `requirements-dev.txt`). Two ruff decisions there are deliberate and should not be "fixed": `RUF001/002/003` (ambiguous-unicode) are ignored because the Turkish docstrings/comments trigger 1600+ false positives, and `UP042` is ignored because switching `class X(str, Enum)` to `StrEnum` would change what `str(member)` returns — the report template relies on the current behaviour via `finding.severity|string`. `ruff format` has **not** been applied to the codebase, so CI runs `ruff check` only. No Docker support yet (listed as planned in README).

## Environment configuration

API keys for threat-intel providers are read from `.env` (via `python-dotenv`, loaded at the top of `main.py`) — never hardcode or log them:

- `VT_API_KEY` (VirusTotal)
- `ABUSEIPDB_API_KEY` (AbuseIPDB)
- `OTX_API_KEY` (AlienVault OTX)

A provider with no key configured is skipped (`ThreatIntelProvider.is_configured()`), not treated as an error.

## Architecture

Pipeline, orchestrated by `main.py`, entirely single-pass / streaming where possible:

```
PCAPParser.parse()          modules/parser.py
        │  list[PacketInfo]
        ▼
build_general_statistics()  modules/statistics.py
        │  GeneralStatistics
        ▼
ThreatDetector.detect()     modules/threat_detector.py
        │  list[ThreatFinding]
        ▼
ThreatIntelService.enrich() modules/threat_intel.py   (parallel via ThreadPoolExecutor, public IPs only)
        │  dict[str, list[NormalizedIOCResult]]
        ▼
Reporter.generate()         modules/reporter.py  →  reports/<clean|malicious>/<stem>_report.html
```

Data contracts live in `modules/models.py` and are shared across every stage: `PacketInfo` (one parsed packet), `ThreatFinding` (one detection-engine result), `GeneralStatistics` (single-pass traffic summary). Both `PacketInfo` and `ThreatFinding` are `frozen=True, slots=True` dataclasses — treated as immutable for chain-of-custody/data-integrity reasons; never mutate them in place, construct a new instance instead. `GeneralStatistics` distribution fields are plain `dict[str, int]`, deliberately converted from `collections.Counter` before being stored — `dataclasses.asdict()` (used by every `to_dict()`) reconstructs a `Counter` incorrectly, so never assign a raw `Counter` to a dataclass field that will be serialized.

**`modules/parser.py`** — `PCAPParser` streams the file with Scapy's `PcapReader` (not `rdpcap`, to stay memory-friendly on large captures) and converts each `scapy.Packet` into a `PacketInfo`. Application-layer protocol detection first checks Scapy layers (DNS/DHCP/NTP/SNMP/TLS/HTTP), then falls back to well-known port numbers. TLS/HTTP layer imports are wrapped in `try/except ImportError` at module level since they may be unavailable depending on the Scapy build. A packet with an unparseable timestamp is kept in the output with `epoch_time=0.0` rather than dropped; a packet that raises during per-field extraction is logged and skipped, but a stream-level failure (`Scapy_Exception`/`OSError`/...) aborts the whole parse via `RuntimeError` (fail-fast at the file level, best-effort at the packet level).

**`modules/statistics.py`** — `build_general_statistics()` walks the packet list exactly once (documented O(N) requirement — do not add a second loop over packets here). Packets with `epoch_time <= 0` (the parser's bad-timestamp sentinel) are counted in totals but excluded from first/last-time, `capture_duration`, and the timeline, otherwise a single corrupt packet would blow out the capture duration to decades.

**`modules/threat_detector.py`** — `ThreatDetector.detect()` runs a fixed list of independent rule methods (`_detect_port_scan`, `_detect_syn_scan`, `_detect_icmp_flood`, `_detect_failed_tcp_connections`, `_detect_dns_tunneling`, `_detect_long_domains`, `_detect_dga_domains`, `_detect_exfiltration`) and concatenates their findings. Most rules bucket packets by `(src_ip, dst_ip)` (or `(src_ip, base_domain)` for DNS tunneling) and slide a time window (`_scan_window_for_threshold` is the shared sliding-window implementation reused by the two port-scan-style rules) over sorted-by-time packets, matching against thresholds defined in `config.py`. New detection rules should follow this same shape: a `config.py` threshold/window pair, a private `_detect_*` method, appended to the list in `detect()`. `_is_egress_traffic`/`_is_public_ip`-style checks (`ipaddress.is_global`) are how "traffic leaving the internal network" is identified for exfiltration and for excluding private/reserved IPs from external TI lookups. `_detect_port_scan` additionally filters out probable *response* traffic via `_is_probable_response_packet` (service source port → ephemeral destination port, using `config.EPHEMERAL_PORT_MIN`): without it, a plain DNS/NTP/QUIC server answering a client on a fresh ephemeral port each time reads as "N distinct ports contacted" and turns every clean capture into a HIGH-severity port scan. The documented trade-off is that source-port-spoofing scans (`nmap -g 53`) are missed by this rule; `_detect_syn_scan` still catches TCP scans at the flag level, independently of this filter.

**`modules/threat_intel.py`** — Strictly scoped to enrichment only (`IP → provider queries → NormalizedIOCResult`); it does not do scoring, severity, or report generation by design (YAGNI, left to `reporter.py`). Each provider is a `ThreatIntelProvider` subclass implementing only `query()` and, optionally, `_extract_provider_error()` for its own error JSON shape; shared HTTP mechanics (timeout, retry-aware session, error classification into `ProviderErrorCode`) live in the base class's `_execute_request`. `NormalizedIOCResult.is_malicious` is a tri-state (`True`/`False`/`None`) — `None` means the provider couldn't render a verdict (e.g., no data), and must not be treated as "clean". `ThreatIntelService.enrich()` caches per-IP results and never raises on a provider failure — a provider exception becomes an error `NormalizedIOCResult` instead, so one bad provider can't take down enrichment for the rest. Only globally-routable IPs are queried (`main.py`'s `_is_public_ip` filter) since private/reserved ranges are meaningless to these providers and some (e.g. OTX) reject them outright.

**`modules/reporter.py`** — Strict separation between view (`templates/report.html.j2`, Jinja2) and generation logic (this file). `ChartBuilder` turns statistics into base64-embedded matplotlib PNGs (`matplotlib.use("Agg")`, no GUI backend) plus `TableRow` data — it has no knowledge of Jinja2 or the filesystem, so it's unit-testable in isolation. `compute_risk_summary` is a pure function (`findings → RiskSummary`) driven by the severity-weight table (`_SEVERITY_WEIGHT`) and ordered threshold table (`_RISK_THRESHOLDS`); the exact threshold values are pinned to test expectations (see the comment in `reporter.py`) — treat them as an API contract, not a tunable. `risk_score` is an *unbounded* weighted sum (20 HIGH findings = 300) and the threshold table is calibrated against that raw value, so it must never be scaled or clamped; the template renders it as-is. `risk_score_normalized` (clamped to `_RISK_SCORE_DISPLAY_MAX`) exists purely so the progress bar's `width: N%` cannot overflow its container — use it for presentation only, never for comparisons or thresholds. `Reporter` itself only orchestrates: validates input, calls `ChartBuilder`/`compute_risk_summary`, renders the template, writes the file. The generated report is a single HTML file with no external references (charts inlined as base64) so it can be opened offline on an air-gapped forensic workstation.

**`config.py`** — Single source of truth for all thresholds, time windows, directory paths (auto-created on import), API base URLs/env-var names, and lookup tables (`PROTOCOL_MAP`, `DNS_QTYPE_MAP`). Detection rules and report thresholds should read from here rather than hardcoding values inline. `TOOL_VERSION` also lives here and is the *only* place the version is written — `main.py`'s banner, `reporter._TOOL_VERSION` (which the report prints under "Araç Sürümü") and `pyproject.toml` must all agree; a test asserts this, because three copies had already drifted apart once.

## Testing conventions

- 213 tests across `tests/test_{main,parser,statistics,threat_detector,threat_intel,reporter}.py`, no `conftest.py` — fixtures are defined locally per test file.
- Tests must never write into the project tree. `Reporter.generate()` derives its output path from `config.REPORTS_DIR`, so any test that calls it has to monkeypatch that attribute (`test_reporter.py` does it via an autouse `isolated_reports_dir` fixture, `test_main.py` inline); without it every run left artifacts in the real `reports/clean/`.
- `tests/snapshots/report_snapshot.html` is used for reporter snapshot-style assertions.
- Samples for manual/integration testing live under `samples/clean/` and `samples/malicious/`; actual `.pcap`/`.pcapng` files are gitignored (only `.gitkeep` is tracked) — don't assume a sample file exists in a fresh checkout.


# Proje Talimatları

## Python Ortamı ve Testler
- Projenin sanal ortamı: `./venv`
- Testleri çalıştırmak için şu komutu kullan: `source venv/bin/activate && pytest`
- Kodları çalıştırmadan önce `venv` ortamının aktif olduğundan emin ol.
- Analiz ve PCAP çıktılarını `reports/` klasöründe kontrol et.