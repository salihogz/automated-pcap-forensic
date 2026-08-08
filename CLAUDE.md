# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## Read this first

@docs/ARCHITECTURE.md

That file is the single source of truth for how the pipeline works, what every
module is responsible for, and which design decisions must not be "simplified"
away. It is written for any developer, not only for an assistant — keep it that
way, and put new architectural reasoning there rather than here.

## Conventions specific to working in this repo

- **Comments and docstrings are Turkish**; identifiers, README and `docs/` are
  English. Match the surrounding file when editing.
- Comments here carry *rationale*, not restatement. When a fix prevents a real
  failure, record the failure — that is the house style and it is load-bearing.
- Never widen a detection rule or a threat-intel verdict without a regression
  test. Both directions are dangerous in a forensic tool: calling something
  clean that isn't, and calling something malicious on a single weak signal.
- Run `ruff check .` and `pytest` before claiming anything is done.

# Proje Talimatları

## Python Ortamı ve Testler
- Projenin sanal ortamı: `./venv`
- Testleri çalıştırmak için şu komutu kullan: `source venv/bin/activate && pytest`
- Kodları çalıştırmadan önce `venv` ortamının aktif olduğundan emin ol.
- Analiz ve PCAP çıktılarını `reports/` klasöründe kontrol et.
