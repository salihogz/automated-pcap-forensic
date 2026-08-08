# modules/exporters/__init__.py
"""
Automated PCAP Forensic Analysis Tool - Export biçimleri.

Tek dosyalık HTML raporu (`modules/reporter.py`) analistin okuması içindir.
Bu paket ise analiz sonucunu BAŞKA araçlara ve başka bağlamlara taşır:

    json  -> SIEM'e besleme, korelasyon, iki analizin diff'i (kayıpsız, ham)
    csv   -> Excel/pivot, IOC listesi çıkarma, timeline aracına aktarım
    pdf   -> basılabilir/imzalanabilir, sayfa numaralı adli belge

Yeni bir biçim eklemek için: `Exporter` alt sınıfı yazılır ve `EXPORTERS`
sözlüğüne eklenir. Mevcut hiçbir biçim değişmez (OCP).
"""
from typing import Final

from modules.exporters.base import Exporter, ExportError, ExportPayload
from modules.exporters.csv_exporter import CSVExporter
from modules.exporters.json_exporter import JSONExporter
from modules.exporters.pdf_exporter import PDFExporter

#: CLI'daki `--format` değerlerinden export sınıflarına eşleme. Sıra,
#: birden fazla biçim istendiğinde çalıştırma sırasını belirler.
EXPORTERS: Final[dict[str, type[Exporter]]] = {
    JSONExporter.name: JSONExporter,
    CSVExporter.name: CSVExporter,
    PDFExporter.name: PDFExporter,
}

#: `--format` seçeneğinin kabul ettiği biçim adları ("html" main.py'de
#: doğrudan Reporter'a gider, bu pakete ait değildir).
AVAILABLE_FORMATS: Final[tuple[str, ...]] = tuple(EXPORTERS)

__all__ = [
    "AVAILABLE_FORMATS",
    "EXPORTERS",
    "CSVExporter",
    "ExportError",
    "ExportPayload",
    "Exporter",
    "JSONExporter",
    "PDFExporter",
]
