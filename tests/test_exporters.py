"""
Export katmanı (JSON / CSV / PDF) test paketi.

Bu testlerin ağırlık merkezi "dosya üretildi mi" değil, ÇIKTININ ANLAMIDIR:
üç durumlu `is_malicious` alanının hiçbir biçimde "temiz"e yuvarlanmaması,
bulguların makine biçimlerinde HAM (gruplanmamış) kalması, TI uzlaşısının
HTML raporla birebir aynı çıkması ve Türkçe karakterlerin PDF'te bozulmaması.
Bunların her biri, sessizce yanlış bir adli belge üretebilecek hata
sınıflarıdır.
"""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path

import matplotlib
import pytest

# Başsız ortamda GUI backend'i devre dışı (grafik üreten PDF testleri için).
matplotlib.use("Agg")

import config
from modules.exporters import AVAILABLE_FORMATS, EXPORTERS, ExportError, ExportPayload
from modules.exporters import pdf_exporter as pdf_mod
from modules.exporters.csv_exporter import CSVExporter
from modules.exporters.json_exporter import JSONExporter, _json_default
from modules.exporters.pdf_exporter import PDFExporter
from modules.models import GeneralStatistics, ThreatFinding, ThreatSeverity
from modules.output_paths import resolve_output_dir
from modules.threat_intel import NormalizedIOCResult, ProviderErrorCode

FIXED_QUERY_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


# ======================================================================
# Fixtures
# ======================================================================


@pytest.fixture
def capture_file(tmp_path: Path) -> Path:
    """İçeriği bilinen sahte bir capture dosyası (SHA-256 doğrulaması için)."""
    path = tmp_path / "malicious" / "ornek.pcapng"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"PCAP-TEST-BYTES")
    return path


@pytest.fixture
def statistics() -> GeneralStatistics:
    return GeneralStatistics(
        total_packets=1500,
        total_bytes=1048576,
        first_packet_time=1609459200.0,
        last_packet_time=1609459320.0,
        capture_duration=120.0,
        protocol_distribution={"TCP": 1000, "DNS": 400, "ICMP": 100},
        network_protocol_distribution={"IPv4": 1400, "IPv6": 100},
        transport_protocol_distribution={"TCP": 1000, "UDP": 400, "ICMP": 100},
        application_protocol_distribution={"DNS": 400, "TLS": 900, "QUIC": 60},
        top_bandwidth_hosts=[("192.168.1.50", 524288)],
        top_source_ips=[("192.168.1.50", 900), ("10.0.0.7", 300)],
        top_destination_ips=[("93.184.216.34", 800)],
        top_tcp_ports=[(443, 900), (80, 100)],
        top_udp_ports=[(53, 400)],
        timeline={1609459200.0: 700, 1609459260.0: 800},
        ip_hostname_map={"93.184.216.34": "example.com"},
    )


@pytest.fixture
def minimal_statistics() -> GeneralStatistics:
    """Grafik üretmeyen (boş dağılımlı) istatistik -- PDF testlerini hızlandırır."""
    return GeneralStatistics(0, 0, 0.0, 0.0, 0.0, {}, {}, {}, {}, [], [], [], [], [], {})


@pytest.fixture
def findings() -> list[ThreatFinding]:
    """Farklı önem derecelerinden bulgular; ikisi kasıtlı olarak AYNI kuraldan.

    Aynı (rule_id, source, destination) üçlüsünün iki kez geçmesi, "makine
    biçimleri ham veriyi korur, PDF gruplar" ayrımını test edilebilir kılar.
    """
    return [
        ThreatFinding(
            rule_id="SEC-PORT-SCAN-001",
            title="Port Taraması",
            severity=ThreatSeverity.HIGH,
            description="10.0.0.7 adresinden çok sayıda porta erişim.",
            evidence={"distinct_port_count": 23, "first_seen_epoch": 1609459200.0},
            source="10.0.0.7",
            destination="192.168.1.50",
            timestamp=1609459200.0,
        ),
        ThreatFinding(
            rule_id="SEC-PORT-SCAN-001",
            title="Port Taraması",
            severity=ThreatSeverity.HIGH,
            description="10.0.0.7 adresinden çok sayıda porta erişim.",
            evidence={"distinct_port_count": 31, "first_seen_epoch": 1609459260.0},
            source="10.0.0.7",
            destination="192.168.1.50",
            timestamp=1609459260.0,
        ),
        ThreatFinding(
            rule_id="SEC-EXFIL-001",
            title="Şüpheli Veri Sızdırma",
            severity=ThreatSeverity.CRITICAL,
            description="Dışarıya yüksek hacimli aktarım tespit edildi.",
            evidence={"total_megabytes": 120.5, "domains": ["çıkış.example.com"]},
            source="192.168.1.50",
            destination="93.184.216.34",
            timestamp=1609459300.0,
        ),
    ]


@pytest.fixture
def threat_intel() -> dict[str, list[NormalizedIOCResult]]:
    """Üç durumun hepsini içeren TI sonucu: zararlı, temiz ve HÜKÜM VERİLEMEYEN."""

    def result(
        source: str,
        is_malicious: bool | None,
        raw_score: float | int | None = None,
        error: ProviderErrorCode | None = None,
    ) -> NormalizedIOCResult:
        return NormalizedIOCResult(
            source=source,
            ip="93.184.216.34",
            is_malicious=is_malicious,
            raw_score=raw_score,
            categories=("Port Scan",) if is_malicious else (),
            last_seen=None,
            queried_at=FIXED_QUERY_TIME,
            provider_error_code=error,
            provider_error_message="zaman aşımı" if error else None,
            confidence=0.9 if is_malicious else None,
        )

    return {
        "93.184.216.34": [
            result("VirusTotal", True, raw_score=7),
            result("AbuseIPDB", False, raw_score=0),
            # Yanıt veremeyen sağlayıcı: is_malicious None.
            result("AlienVault OTX", None, error=ProviderErrorCode.TIMEOUT),
        ]
    }


@pytest.fixture
def payload(
    statistics: GeneralStatistics,
    findings: list[ThreatFinding],
    threat_intel: dict[str, list[NormalizedIOCResult]],
    capture_file: Path,
) -> ExportPayload:
    return ExportPayload.build(
        statistics=statistics,
        findings=findings,
        threat_intel=threat_intel,
        source_file=capture_file,
        analysis_duration=1.25,
    )


# ======================================================================
# output_paths -- HTML raporu ve export'ların ORTAK klasör kuralı
# ======================================================================


@pytest.mark.parametrize(
    ("parent_name", "expected"),
    [("malicious", "malicious"), ("clean", "clean"), ("MALICIOUS", "malicious")],
)
def test_resolve_output_dir_uses_parent_folder_category(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, parent_name: str, expected: str
):
    monkeypatch.setattr(config, "REPORTS_DIR", tmp_path / "reports")
    source = tmp_path / parent_name / "x.pcapng"

    assert resolve_output_dir(source) == tmp_path / "reports" / expected


def test_resolve_output_dir_falls_back_to_clean_for_unknown_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(config, "REPORTS_DIR", tmp_path / "reports")

    assert resolve_output_dir(tmp_path / "rastgele" / "x.pcapng") == tmp_path / "reports" / "clean"


def test_resolve_output_dir_reads_reports_dir_at_call_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Import anında sabitlenmiş olsaydı testler proje ağacına yazmaya devam ederdi."""
    monkeypatch.setattr(config, "REPORTS_DIR", tmp_path / "ilk")
    first = resolve_output_dir(tmp_path / "clean" / "x.pcapng")
    monkeypatch.setattr(config, "REPORTS_DIR", tmp_path / "ikinci")
    second = resolve_output_dir(tmp_path / "clean" / "x.pcapng")

    assert first != second


# ======================================================================
# ExportPayload
# ======================================================================


def test_payload_computes_sha256_of_source_file(payload: ExportPayload):
    # b"PCAP-TEST-BYTES" için sabit özet.
    import hashlib

    assert payload.sha256 == hashlib.sha256(b"PCAP-TEST-BYTES").hexdigest()


def test_payload_uses_precomputed_sha256_without_rereading(
    statistics: GeneralStatistics, capture_file: Path
):
    """Verilen özet aynen kullanılmalı: aynı delil dosyası iki kez okunmamalı."""
    built = ExportPayload.build(
        statistics=statistics,
        findings=[],
        threat_intel={},
        source_file=capture_file,
        analysis_duration=0.0,
        sha256="ONCEDEN-HESAPLANMIS",
    )

    assert built.sha256 == "ONCEDEN-HESAPLANMIS"


def test_payload_sha256_is_none_when_file_is_unreadable(
    statistics: GeneralStatistics, tmp_path: Path
):
    """Fail Soft: okunamayan dosya özeti export'u durdurmaz, None kalır."""
    built = ExportPayload.build(
        statistics=statistics,
        findings=[],
        threat_intel={},
        source_file=tmp_path / "yok.pcapng",
        analysis_duration=0.0,
    )

    assert built.sha256 is None


def test_payload_risk_summary_uses_raw_ungrouped_findings(payload: ExportPayload):
    """Tekrar eden bulgular gruplanıp skor DÜŞMEMELİ: 2 HIGH + 1 CRITICAL = 60."""
    assert payload.risk_summary.total_findings == 3
    assert payload.risk_summary.risk_score == 15 + 15 + 30


def test_payload_findings_are_immutable_tuple(payload: ExportPayload):
    assert isinstance(payload.findings, tuple)


def test_payload_generated_at_carries_timezone(payload: ExportPayload):
    """Adli belgede saat dilimsiz zaman damgası kanıt değeri taşımaz."""
    assert payload.generated_at.tzinfo is not None


def test_payload_tool_version_matches_config(payload: ExportPayload):
    assert payload.tool_version == config.TOOL_VERSION


# ======================================================================
# Kayıt defteri
# ======================================================================


def test_registry_exposes_all_three_formats():
    assert set(EXPORTERS) == {"json", "csv", "pdf"}
    assert AVAILABLE_FORMATS == ("json", "csv", "pdf")


def test_registry_classes_declare_matching_names():
    for name, exporter_cls in EXPORTERS.items():
        assert exporter_cls.name == name


# ======================================================================
# JSON
# ======================================================================


def test_json_export_writes_single_file_named_after_capture(payload: ExportPayload, tmp_path: Path):
    written = JSONExporter().export(payload, tmp_path / "out")

    assert written == [tmp_path / "out" / "ornek_report.json"]
    assert written[0].exists()


def test_json_export_is_valid_and_versioned(payload: ExportPayload, tmp_path: Path):
    path = JSONExporter().export(payload, tmp_path)[0]
    document = json.loads(path.read_text(encoding="utf-8"))

    assert document["schema_version"] == 1
    assert document["tool"]["version"] == config.TOOL_VERSION
    assert document["analysis"]["source_file"] == "ornek.pcapng"
    assert document["analysis"]["sha256"] == payload.sha256


def test_json_export_keeps_findings_raw_and_ungrouped(payload: ExportPayload, tmp_path: Path):
    """Makine biçimi kayıpsız olmalı: iki ayrı port-scan olayı iki kayıt kalmalı."""
    document = json.loads(JSONExporter().export(payload, tmp_path)[0].read_text(encoding="utf-8"))

    assert len(document["findings"]) == 3
    port_scans = [f for f in document["findings"] if f["rule_id"] == "SEC-PORT-SCAN-001"]
    assert len(port_scans) == 2
    assert {f["evidence"]["distinct_port_count"] for f in port_scans} == {23, 31}


def test_json_export_serializes_severity_as_plain_value(payload: ExportPayload, tmp_path: Path):
    """"ThreatSeverity.HIGH" değil "HIGH" yazılmalı (Enum tabanına bağımlı kalmamak için)."""
    document = json.loads(JSONExporter().export(payload, tmp_path)[0].read_text(encoding="utf-8"))

    assert {f["severity"] for f in document["findings"]} == {"HIGH", "CRITICAL"}


def test_json_export_preserves_tristate_is_malicious(payload: ExportPayload, tmp_path: Path):
    """None -> null olarak korunmalı; ASLA false ("temiz") ile birleştirilmemeli."""
    document = json.loads(JSONExporter().export(payload, tmp_path)[0].read_text(encoding="utf-8"))
    providers = {p["provider"]: p for p in document["threat_intel"][0]["providers"]}

    assert providers["VirusTotal"]["is_malicious"] is True
    assert providers["AbuseIPDB"]["is_malicious"] is False
    assert providers["AlienVault OTX"]["is_malicious"] is None
    assert providers["AlienVault OTX"]["error_code"] == "TIMEOUT"


def test_json_export_consensus_counts_answering_providers_only(
    payload: ExportPayload, tmp_path: Path
):
    """Yanıt veremeyen sağlayıcı paydaya dahil edilmemeli (uzlaşı reporter'dan gelir)."""
    document = json.loads(JSONExporter().export(payload, tmp_path)[0].read_text(encoding="utf-8"))
    consensus = document["threat_intel"][0]["consensus"]

    assert consensus["total_providers"] == 3
    assert consensus["answered_providers"] == 2
    assert consensus["malicious_providers"] == 1
    assert consensus["label"] == "ÇELİŞKİLİ"


def test_json_export_writes_iso_timestamps(payload: ExportPayload, tmp_path: Path):
    document = json.loads(JSONExporter().export(payload, tmp_path)[0].read_text(encoding="utf-8"))

    assert document["analysis"]["generated_at"].startswith("20")
    queried = document["threat_intel"][0]["providers"][0]["queried_at"]
    assert queried == FIXED_QUERY_TIME.isoformat()


def test_json_export_keeps_turkish_characters_readable(payload: ExportPayload, tmp_path: Path):
    raw = JSONExporter().export(payload, tmp_path)[0].read_text(encoding="utf-8")

    assert "Şüpheli Veri Sızdırma" in raw  # Ş kaçışına dönüşmemeli


def test_json_default_rejects_unknown_types():
    """Bilinmeyen tip sessizce str()'e düşürülmemeli (ham repr sızıntısı riski)."""

    class Foo:
        pass

    with pytest.raises(TypeError):
        _json_default(Foo())


def test_json_default_serializes_sets_deterministically():
    assert _json_default({"b", "a"}) == ["a", "b"]


def test_json_export_raises_export_error_when_path_is_unwritable(
    payload: ExportPayload, tmp_path: Path
):
    # Hedef "dizin" aslında bir dosya -> mkdir başarısız olur.
    blocker = tmp_path / "engel"
    blocker.write_text("dosya", encoding="utf-8")

    with pytest.raises(ExportError):
        JSONExporter().export(payload, blocker)


# ======================================================================
# CSV
# ======================================================================


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def test_csv_export_writes_three_named_files(payload: ExportPayload, tmp_path: Path):
    written = CSVExporter().export(payload, tmp_path)

    assert [p.name for p in written] == [
        "ornek_findings.csv",
        "ornek_threat_intel.csv",
        "ornek_statistics.csv",
    ]
    assert all(p.exists() for p in written)


def test_csv_files_start_with_bom_for_excel(payload: ExportPayload, tmp_path: Path):
    """BOM olmadan Excel, Türkçe karakterleri bozarak açar."""
    for path in CSVExporter().export(payload, tmp_path):
        assert path.read_bytes().startswith(b"\xef\xbb\xbf")


def test_csv_findings_keep_every_raw_row(payload: ExportPayload, tmp_path: Path):
    rows = _read_csv(CSVExporter().export(payload, tmp_path)[0])

    assert len(rows) == 3
    assert sum(1 for row in rows if row["rule_id"] == "SEC-PORT-SCAN-001") == 2


def test_csv_findings_evidence_column_is_parseable_json(payload: ExportPayload, tmp_path: Path):
    """Ham Python repr'ı değil, ayrıştırılabilir JSON yazılmalı."""
    rows = _read_csv(CSVExporter().export(payload, tmp_path)[0])
    evidence = json.loads(rows[0]["evidence_json"])

    assert evidence["distinct_port_count"] == 23


def test_csv_findings_carry_both_epoch_and_iso_timestamps(payload: ExportPayload, tmp_path: Path):
    rows = _read_csv(CSVExporter().export(payload, tmp_path)[0])

    assert rows[0]["timestamp_epoch"] == "1609459200.0"
    assert rows[0]["timestamp_iso"].startswith("2021-01-01")


def test_csv_findings_preserve_turkish_text(payload: ExportPayload, tmp_path: Path):
    rows = _read_csv(CSVExporter().export(payload, tmp_path)[0])
    titles = {row["title"] for row in rows}

    assert "Şüpheli Veri Sızdırma" in titles


def test_csv_threat_intel_has_one_row_per_provider(payload: ExportPayload, tmp_path: Path):
    rows = _read_csv(CSVExporter().export(payload, tmp_path)[1])

    assert len(rows) == 3
    assert {row["provider"] for row in rows} == {"VirusTotal", "AbuseIPDB", "AlienVault OTX"}


def test_csv_threat_intel_marks_unanswered_provider_as_unknown(
    payload: ExportPayload, tmp_path: Path
):
    """Boş hücre "temiz" diye okunabilir; belirsizlik açıkça yazılmalı."""
    rows = {row["provider"]: row for row in _read_csv(CSVExporter().export(payload, tmp_path)[1])}

    assert rows["VirusTotal"]["is_malicious"] == "true"
    assert rows["AbuseIPDB"]["is_malicious"] == "false"
    assert rows["AlienVault OTX"]["is_malicious"] == "unknown"
    assert rows["AlienVault OTX"]["error_code"] == "TIMEOUT"


def test_csv_threat_intel_repeats_consensus_on_every_row(payload: ExportPayload, tmp_path: Path):
    rows = _read_csv(CSVExporter().export(payload, tmp_path)[1])

    assert {row["consensus_label"] for row in rows} == {"ÇELİŞKİLİ"}
    assert {row["answered_providers"] for row in rows} == {"2"}


def test_csv_statistics_uses_long_format_with_all_categories(
    payload: ExportPayload, tmp_path: Path
):
    rows = _read_csv(CSVExporter().export(payload, tmp_path)[2])
    categories = {row["category"] for row in rows}

    assert {"summary", "protocol_distribution", "top_source_ips", "timeline"} <= categories
    summary = {row["key"]: row["value"] for row in rows if row["category"] == "summary"}
    assert summary["total_packets"] == "1500"


def test_csv_statistics_sorts_distributions_by_value_desc(payload: ExportPayload, tmp_path: Path):
    """Rapordaki grafiklerle aynı sıra korunmalı (çoktan aza)."""
    rows = _read_csv(CSVExporter().export(payload, tmp_path)[2])
    protocols = [r["key"] for r in rows if r["category"] == "protocol_distribution"]

    assert protocols == ["TCP", "DNS", "ICMP"]


def test_csv_statistics_writes_full_resolution_timeline(payload: ExportPayload, tmp_path: Path):
    rows = _read_csv(CSVExporter().export(payload, tmp_path)[2])
    timeline = [row for row in rows if row["category"] == "timeline"]

    assert len(timeline) == 2
    assert timeline[0]["value"] == "700"


def test_csv_export_raises_export_error_when_path_is_unwritable(
    payload: ExportPayload, tmp_path: Path
):
    blocker = tmp_path / "engel"
    blocker.write_text("dosya", encoding="utf-8")

    with pytest.raises(ExportError):
        CSVExporter().export(payload, blocker)


# ======================================================================
# PDF
# ======================================================================


def _pdf_text(path: Path) -> str:
    """PDF'in tüm metnini, boşlukları tekilleştirerek döndürür.

    Tekilleştirme şart: ReportLab metni hücre genişliğine göre sarar ve pypdf
    her satır sonuna "\\n" koyar. Ham metinde "KANIT DEĞİLDİR" gibi bir ifade,
    yalnızca satır sonuna denk geldiği için "KANIT\\nDEĞİLDİR" olarak görünür;
    testin sayfa düzenine değil İÇERİĞE bakması gerekir.
    """
    pypdf = pytest.importorskip("pypdf")
    reader = pypdf.PdfReader(str(path))
    return " ".join("\n".join(page.extract_text() for page in reader.pages).split())


def test_pdf_export_writes_single_pdf_file(payload: ExportPayload, tmp_path: Path):
    written = PDFExporter().export(payload, tmp_path)

    assert written == [tmp_path / "ornek_report.pdf"]
    assert written[0].read_bytes().startswith(b"%PDF")


def test_pdf_contains_chain_of_custody_and_risk_summary(payload: ExportPayload, tmp_path: Path):
    text = _pdf_text(PDFExporter().export(payload, tmp_path)[0])

    assert "PCAP ADLİ ANALİZ RAPORU" in text
    assert "ornek.pcapng" in text
    assert payload.sha256 in text
    assert payload.risk_summary.risk_level in text


def test_pdf_renders_turkish_characters_without_corruption(payload: ExportPayload, tmp_path: Path):
    """Gömülü Helvetica ğ/ş/ı/İ içermez; DejaVu gömülmezse bu metin bozulur."""
    text = _pdf_text(PDFExporter().export(payload, tmp_path)[0])

    assert "Şüpheli Veri Sızdırma" in text
    assert "Tehdit Bulguları" in text


def test_pdf_numbers_every_page_with_total(payload: ExportPayload, tmp_path: Path):
    """Sayfa X / Y: eksik sayfa ancak toplam biliniyorsa fark edilir."""
    path = PDFExporter().export(payload, tmp_path)[0]
    pypdf = pytest.importorskip("pypdf")
    total = len(pypdf.PdfReader(str(path)).pages)
    text = _pdf_text(path)

    assert total >= 1
    for page_number in range(1, total + 1):
        assert f"Sayfa {page_number} / {total}" in text


def test_pdf_groups_recurring_findings(payload: ExportPayload, tmp_path: Path):
    """Aynı tespitin tekrarları tek satırda özetlenmeli (JSON/CSV'nin aksine)."""
    text = _pdf_text(PDFExporter().export(payload, tmp_path)[0])

    assert text.count("SEC-PORT-SCAN-001") == 1
    assert "Tekrar Sayısı" in text


def test_pdf_states_that_no_findings_is_not_proof_of_safety(
    minimal_statistics: GeneralStatistics, capture_file: Path, tmp_path: Path
):
    empty = ExportPayload.build(
        statistics=minimal_statistics,
        findings=[],
        threat_intel={},
        source_file=capture_file,
        analysis_duration=0.0,
    )
    text = _pdf_text(PDFExporter().export(empty, tmp_path)[0])

    assert "KANITI DEĞİLDİR" in text
    assert "temiz olduğu anlamına GELMEZ" in text


def test_pdf_lists_threat_intel_with_consensus(payload: ExportPayload, tmp_path: Path):
    text = _pdf_text(PDFExporter().export(payload, tmp_path)[0])

    assert "93.184.216.34" in text
    assert "ÇELİŞKİLİ" in text
    # Hüküm veremeyen sağlayıcı "temiz" gibi görünmemeli.
    assert "yanıt yok" in text


def test_pdf_raises_export_error_when_reportlab_is_missing(
    payload: ExportPayload, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Eksik opsiyonel bağımlılık net bir mesajla bildirilmeli, çökmeyle değil."""
    monkeypatch.setattr(pdf_mod, "_REPORTLAB_IMPORT_ERROR", "No module named 'reportlab'")

    with pytest.raises(ExportError, match="reportlab"):
        PDFExporter().export(payload, tmp_path)


def test_pdf_falls_back_to_builtin_font_when_dejavu_is_missing(
    minimal_statistics: GeneralStatistics,
    capture_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    """Fail Soft: yazı tipi bulunamazsa belge yine üretilmeli, sadece uyarılmalı."""
    monkeypatch.setattr(pdf_mod, "_fonts_ready", None)
    monkeypatch.setattr(pdf_mod.matplotlib, "get_data_path", lambda: str(tmp_path / "yok"))

    payload = ExportPayload.build(
        statistics=minimal_statistics,
        findings=[],
        threat_intel={},
        source_file=capture_file,
        analysis_duration=0.0,
    )
    with caplog.at_level("WARNING"):
        written = PDFExporter().export(payload, tmp_path)

    assert written[0].read_bytes().startswith(b"%PDF")
    assert "DejaVu Sans" in caplog.text


def test_pdf_escapes_markup_characters_from_capture_data(
    minimal_statistics: GeneralStatistics, capture_file: Path, tmp_path: Path
):
    """Capture'dan gelen "<" / "&" karakterleri belge üretimini bozmamalı."""
    hostile = ThreatFinding(
        rule_id="SEC-TEST-001",
        title="<script>alert(1)</script> & <b>kalın</b>",
        severity=ThreatSeverity.LOW,
        description="Kanıtta işaretleme karakterleri var: <img src=x> & ampersand.",
        evidence={"domain": "<evil>&co.example.com"},
        source="10.0.0.1",
    )
    payload = ExportPayload.build(
        statistics=minimal_statistics,
        findings=[hostile],
        threat_intel={},
        source_file=capture_file,
        analysis_duration=0.0,
    )

    text = _pdf_text(PDFExporter().export(payload, tmp_path)[0])

    assert "<script>alert(1)</script>" in text
    assert "<evil>&co.example.com" in text
