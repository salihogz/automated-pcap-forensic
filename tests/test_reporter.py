"""
Production-Grade Comprehensive Integration, Unit & DOM Regression Test Suite for Reporter Module.

Addresses deep production contract details:
- Cleaned unused imports.
- Explicit import contracts (modules.reporter, modules.threat_intel).
- Standardized fixed timestamps across all fixtures and tests for snapshot determinism.
- Validates direct _render() Jinja2 errors with threat_intel support.
- Comprehensive DOM validation including Threat Intelligence section CSS selectors.
- Strict pipeline assertions verifying IOC enrichment tables, scores, and threat classifications.
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

import matplotlib
import pytest

# Force non-interactive GUI backend for headless environments
matplotlib.use("Agg")

from bs4 import BeautifulSoup
from jinja2 import TemplateError, TemplateNotFound

from modules import reporter as r
from modules.models import GeneralStatistics, ThreatFinding, ThreatSeverity
from modules.threat_intel import NormalizedIOCResult

# Fixed reference timestamp for deterministic tests
FIXED_TEST_NOW = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)

# ---------------------------------------------------------------------------
# 1. Structural & Dataclass Contract Assertions
# ---------------------------------------------------------------------------


def test_core_models_structural_contract():
    """Validates core models structural contracts."""
    assert hasattr(GeneralStatistics, "__dataclass_fields__")
    assert hasattr(ThreatFinding, "__dataclass_fields__")
    assert issubclass(r.ReportGenerationError, Exception)


# ---------------------------------------------------------------------------
# 2. Production Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolated_reports_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Rapor çıktılarını testin geçici dizinine yönlendirir.

    `Reporter.generate()` çıktı yolunu `config.REPORTS_DIR`'dan türetir; testler
    kaynak pcap'i tmp_path'te üretse bile rapor PROJENİN gerçek `reports/`
    dizinine yazılıyordu. Sonuç: her `pytest` çalışması depoya
    `reports/clean/test_report.html`, `snapshot_report.html` gibi artefaktlar
    bırakıyordu ve bir testin çıktısı bir sonraki koşuda hâlâ oradaydı
    (testler arası sızıntı). Autouse: tek bir testin bunu atlaması yeterince
    kirlilik yaratacağı için opt-in bırakılmadı.
    """
    reports_dir = tmp_path / "reports"
    monkeypatch.setattr(r.config, "REPORTS_DIR", reports_dir)
    return reports_dir


@pytest.fixture
def real_template_dir() -> Path:
    candidates = [
        Path(__file__).parent.parent / "templates",
        Path(__file__).parent / "templates",
        Path("templates"),
    ]
    for p in candidates:
        if (p / "report.html.j2").exists():
            return p
    pytest.skip("templates/report.html.j2 directory not found.")


@pytest.fixture
def populated_statistics() -> GeneralStatistics:
    return GeneralStatistics(
        total_packets=15000,
        total_bytes=10485760,
        first_packet_time=1609459200.0,
        last_packet_time=1609459320.0,
        capture_duration=120.0,
        protocol_distribution={"TCP": 10000, "UDP": 4000, "ICMP": 1000},
        network_protocol_distribution={"IPv4": 14000, "IPv6": 1000},
        transport_protocol_distribution={"TCP": 10000, "UDP": 4000, "ICMP": 1000},
        application_protocol_distribution={"HTTP": 4000, "HTTPS": 5000, "DNS": 1000},
        top_bandwidth_hosts=[("192.168.1.50", 5242880), ("10.0.0.1", 2621440)],
        top_source_ips=[("192.168.1.50", 5000), ("10.0.0.1", 3000)],
        top_destination_ips=[("10.0.0.2", 6000), ("192.168.1.1", 4000)],
        top_tcp_ports=[(80, 4000), (443, 5000)],
        top_udp_ports=[(53, 1000), (123, 500)],
        timeline={1609459200.0: 1000, 1609459260.0: 2000},
    )


@pytest.fixture
def sample_finding() -> ThreatFinding:
    return ThreatFinding(
        rule_id="RULE-SQLI-01",
        title="SQL Injection Attack Attempt",
        severity=ThreatSeverity.HIGH,
        description="Potential SQL injection pattern detected in payload parameters",
        evidence={"payload": "' OR 1=1 --", "parameter": "id"},
        source="192.168.1.50:49152",
        destination="10.0.0.1:80",
        timestamp=FIXED_TEST_NOW,
    )


# ---------------------------------------------------------------------------
# 3. Direct Unit Testing for Isolated Reporter Methods (_render, _write, _sort, _validate_inputs)
# ---------------------------------------------------------------------------


class TestReporterIsolatedUnitMethods:
    """Directly tests internal Reporter methods (_sort_findings_by_severity, _write, _render, _validate_inputs)."""

    def test_sort_findings_by_severity_order(self):
        """Verifies explicit ordering: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO."""
        findings = [
            ThreatFinding("R1", "Info", ThreatSeverity.INFO, "", {}, "src", "dst", FIXED_TEST_NOW),
            ThreatFinding("R2", "Low", ThreatSeverity.LOW, "", {}, "src", "dst", FIXED_TEST_NOW),
            ThreatFinding("R3", "High", ThreatSeverity.HIGH, "", {}, "src", "dst", FIXED_TEST_NOW),
            ThreatFinding("R4", "Critical", ThreatSeverity.CRITICAL, "", {}, "src", "dst", FIXED_TEST_NOW),
            ThreatFinding("R5", "Medium", ThreatSeverity.MEDIUM, "", {}, "src", "dst", FIXED_TEST_NOW),
        ]

        # Call production sorting logic via Reporter class
        sorted_findings = r.Reporter._sort_findings_by_severity(findings)

        expected_order = [
            ThreatSeverity.CRITICAL,
            ThreatSeverity.HIGH,
            ThreatSeverity.MEDIUM,
            ThreatSeverity.LOW,
            ThreatSeverity.INFO,
        ]

        actual_order = [f.severity for f in sorted_findings]
        assert actual_order == expected_order

    def test_write_method_success_and_error_handling(self, tmp_path: Path):
        """Validates _write writes files, auto-creates parent directories,
        and wraps write permission errors."""
        target_path = tmp_path / "nested" / "reports" / "test_write.html"
        content = "<html><body>Write Test</body></html>"

        # Successful write with non-existent parent directory auto-creation
        r.Reporter._write(content, target_path)
        assert target_path.exists()
        assert target_path.read_text(encoding="utf-8") == content

        # Test write failure wrapping strictly to ReportGenerationError
        with (
            patch.object(
                Path,
                "write_text",
                side_effect=OSError("Permission denied"),
            ),
            pytest.raises(r.ReportGenerationError),
        ):
            r.Reporter._write(content, target_path)

    def test_render_method_template_not_found_raises_exception(self, tmp_path: Path):
        """Validates that _render raises ReportGenerationError when template file is missing."""
        invalid_reporter = r.Reporter(template_dir=tmp_path)  # Empty dir without report.html.j2

        meta = r.ReportMetadata(source_file="test.pcap", analysis_duration_seconds=1.0)
        stats = GeneralStatistics(10, 100, 0.0, 1.0, 1.0, {}, {}, {}, {}, [], [], [], [], [], {})
        risk_summary = r.compute_risk_summary([])

        with pytest.raises(r.ReportGenerationError) as exc_info:
            invalid_reporter._render(
                statistics=stats,
                findings=[],
                threat_intel={},
                risk_summary=risk_summary,
                metadata=meta,
                charts=[],
            )

        assert "template" in str(exc_info.value).lower() or isinstance(
            exc_info.value.__cause__, (TemplateNotFound, TemplateError)
        )

    def test_generate_public_method_invalid_template_dir(
        self, tmp_path: Path, populated_statistics: GeneralStatistics
    ):
        """Validates public generate() API method raises ReportGenerationError when template_dir is invalid."""
        invalid_reporter = r.Reporter(template_dir=tmp_path)
        pcap_file = tmp_path / "test.pcap"
        pcap_file.touch()

        with pytest.raises(r.ReportGenerationError) as exc_info:
            invalid_reporter.generate(
                statistics=populated_statistics,
                findings=[],
                threat_intel={},
                source_file=pcap_file,
                analysis_duration=1.0,
            )

        assert "template" in str(exc_info.value).lower() or isinstance(
            exc_info.value.__cause__, (TemplateNotFound, TemplateError)
        )

    def test_validate_inputs_validation_rules_and_error_messages(self, tmp_path: Path):
        """Tests input validation logic in Reporter verifying both exception type and message contents."""
        reporter = r.Reporter()
        valid_stats = GeneralStatistics(0, 0, 0.0, 0.0, 0.0, {}, {}, {}, {}, [], [], [], [], [], {})
        valid_meta = r.ReportMetadata(source_file="test.pcap", analysis_duration_seconds=1.0)
        valid_output_path = tmp_path / "report.html"

        # 1. None statistics
        with pytest.raises(r.ReportGenerationError) as exc1:
            reporter._validate_inputs(None, valid_meta, valid_output_path)
        assert "statistics" in str(exc1.value).lower()

        # 2. None metadata
        with pytest.raises(r.ReportGenerationError) as exc2:
            reporter._validate_inputs(valid_stats, None, valid_output_path)
        assert "metadata" in str(exc2.value).lower()

        # 3. Output path is a directory
        with pytest.raises(r.ReportGenerationError) as exc3:
            reporter._validate_inputs(valid_stats, valid_meta, tmp_path)
        exc3_msg = str(exc3.value).lower()
        assert "dizin" in exc3_msg or "directory" in exc3_msg or "path" in exc3_msg

        # 4. Invalid suffix
        invalid_suffix_path = tmp_path / "report.txt"
        with pytest.raises(r.ReportGenerationError) as exc4:
            reporter._validate_inputs(valid_stats, valid_meta, invalid_suffix_path)
        assert ".html" in str(exc4.value).lower()


# ---------------------------------------------------------------------------
# 4. compute_risk_summary, Exact Threshold Boundaries & ChartBuilder
# ---------------------------------------------------------------------------


class TestRiskSummaryAndChartBuilderUnits:
    """Unit tests for compute_risk_summary, exact threshold boundaries,
    and ChartBuilder methods."""

    def test_compute_risk_summary_exact_threshold_boundaries(self):
        """Validates exact risk level assignments for boundary score transitions.

        Note: Assumes production scoring policy (CRITICAL=30, HIGH=15, MEDIUM=5, LOW=4).
        """
        def make_finding(severity: ThreatSeverity) -> ThreatFinding:
            return ThreatFinding("ID", "Title", severity, "", {}, "src", "dst", FIXED_TEST_NOW)

        # Score 0 -> TEMİZ
        assert r.compute_risk_summary([]).risk_level == "TEMİZ"

        # Score 4 (4 x LOW = 4 pts) -> DÜŞÜK (Score >= 4)
        summary_score_4 = r.compute_risk_summary([make_finding(ThreatSeverity.LOW)] * 4)
        assert summary_score_4.risk_level == "DÜŞÜK"

        # Score 5 (1 x MEDIUM = 5 pts) -> ORTA (Score >= 5)
        summary_score_5 = r.compute_risk_summary([make_finding(ThreatSeverity.MEDIUM)])
        assert summary_score_5.risk_level == "ORTA"

        # Score 14 (2 x MEDIUM + 4 x LOW = 14 pts) -> ORTA (Score < 15)
        summary_score_14 = r.compute_risk_summary(
            [make_finding(ThreatSeverity.MEDIUM)] * 2 + [make_finding(ThreatSeverity.LOW)] * 4
        )
        assert summary_score_14.risk_level == "ORTA"

        # Score 15 (1 x HIGH = 15 pts) -> YÜKSEK (Score >= 15)
        summary_score_15 = r.compute_risk_summary([make_finding(ThreatSeverity.HIGH)])
        assert summary_score_15.risk_level == "YÜKSEK"

        # Score 29 (1 x HIGH + 2 x MEDIUM + 4 x LOW = 29 pts) -> YÜKSEK (Score < 30)
        summary_score_29 = r.compute_risk_summary(
            [make_finding(ThreatSeverity.HIGH)]
            + [make_finding(ThreatSeverity.MEDIUM)] * 2
            + [make_finding(ThreatSeverity.LOW)] * 4
        )
        assert summary_score_29.risk_level == "YÜKSEK"

        # Score 30 (1 x CRITICAL = 30 pts) -> KRİTİK (Score >= 30)
        summary_score_30 = r.compute_risk_summary([make_finding(ThreatSeverity.CRITICAL)])
        assert summary_score_30.risk_level == "KRİTİK"

        # Score 59 -> KRİTİK
        summary_score_59 = r.compute_risk_summary(
            [make_finding(ThreatSeverity.CRITICAL)]
            + [make_finding(ThreatSeverity.HIGH)]
            + [make_finding(ThreatSeverity.MEDIUM)] * 2
            + [make_finding(ThreatSeverity.LOW)] * 4
        )
        assert summary_score_59.risk_level == "KRİTİK"

        # Score 60+ -> KRİTİK
        summary_score_60 = r.compute_risk_summary([make_finding(ThreatSeverity.CRITICAL)] * 2)
        assert summary_score_60.risk_level == "KRİTİK"

    def test_risk_score_is_unbounded_but_display_value_stays_in_range(self):
        """Ham skor sınırsız kalmalı, sunum değeri 0-100 aralığında olmalıdır.

        Şablon ilerleme çubuğunu `width: {{ değer }}%` ile çiziyor; ham skor
        sınırsız bir ağırlıklı toplam olduğundan (20 HIGH = 300) doğrudan
        kullanılırsa çubuk kapsayıcısını taşırır. Eşik tablosu ham skora göre
        kalibre edildiği için ham değerin kendisi ASLA kırpılmamalıdır.

        NOT: Sunum değeri skorun kendisi DEĞİL, skorun düştüğü risk bandının
        çubuktaki konumudur (bkz. _compute_risk_bar_position ve
        TestRiskBarAndLevelConsistency). Bu testin eski hâli
        `risk_score_normalized == risk_score` bekliyordu; o eşitlik tam da
        "KRİTİK etiketi + %30 dolu çubuk" çelişkisinin kaynağıydı.
        """
        def make_finding(severity: ThreatSeverity) -> ThreatFinding:
            return ThreatFinding("ID", "Title", severity, "", {}, "src", "dst", FIXED_TEST_NOW)

        summary = r.compute_risk_summary([make_finding(ThreatSeverity.HIGH)] * 20)
        assert summary.risk_score == 300, "ham skor kırpılmamalı (eşik tablosu buna bağlı)"
        assert summary.risk_score_normalized == 100, "çubuk kapsayıcısını taşımamalı"
        assert summary.risk_level == "KRİTİK"

        # Tek bir HIGH: ham skor 15, ama çubuk YÜKSEK bandının başında olmalı.
        high_summary = r.compute_risk_summary([make_finding(ThreatSeverity.HIGH)])
        assert high_summary.risk_score == 15
        assert high_summary.risk_level == "YÜKSEK"
        assert high_summary.risk_score_normalized == 50

        assert r.compute_risk_summary([]).risk_score_normalized == 0

    def test_build_charts_list_exact_count_and_titles(self, populated_statistics: GeneralStatistics):
        """Directly tests Reporter._build_charts_list to verify exact count (7) and keywords in titles."""
        reporter = r.Reporter()
        charts = reporter._build_charts_list(populated_statistics)

        assert isinstance(charts, list)
        assert len(charts) == 7
        assert "Katman Bazlı Protokol Dağılımı" in [c.title for c in charts]

        # Extract chart titles assuming dataclass/object or dict representation
        titles = [getattr(c, "title", c.get("title") if isinstance(c, dict) else None) for c in charts]

        # Verify specific expected production titles exist
        assert any("Protokol" in str(t) or "Protocol" in str(t) for t in titles if t)
        assert any("En Aktif Hostlar" in str(t) or "Talkers" in str(t) for t in titles if t)
        assert any("Bant Genişliği" in str(t) or "Bandwidth" in str(t) for t in titles if t)
        assert any("Zaman" in str(t) or "Timeline" in str(t) for t in titles if t)
        # TCP ve UDP port dağılımları ayrı bölümler olarak üretilmeli:
        # `top_udp_ports` istatistikte hesaplanıp raporda hiç gösterilmiyordu.
        assert "TCP Port Dağılımı" in titles
        assert "UDP Port Dağılımı" in titles

        chart_ids = [c.id for c in charts]
        assert chart_ids.count("udp_port_distribution") == 1

    def test_chart_builder_individual_charts(self, populated_statistics: GeneralStatistics):
        """Tests individual chart building methods using stateless ChartBuilder and explicit parameters."""
        builder = r.ChartBuilder()

        # Execute methods with exact parameter signatures returning tuple[image_base64, table_rows]
        img1, tbl1 = builder.protocol_distribution_chart(populated_statistics.protocol_distribution)
        img2, tbl2 = builder.top_hosts_chart(populated_statistics.top_bandwidth_hosts, "Top Hosts", "Bytes")
        img3, tbl3 = builder.timeline_chart(populated_statistics.timeline)
        img4, tbl4 = builder.port_distribution_chart(dict(populated_statistics.top_tcp_ports))

        for img, tbl in [(img1, tbl1), (img2, tbl2), (img3, tbl3), (img4, tbl4)]:
            assert img is None or isinstance(img, str)
            assert isinstance(tbl, list)

        # Test empty input gracefully with stateless builder
        empty_builder = r.ChartBuilder()
        img_empty, tbl_empty = empty_builder.protocol_distribution_chart({})
        assert img_empty is None or isinstance(img_empty, str)
        assert isinstance(tbl_empty, list)


# ---------------------------------------------------------------------------
# 5. BeautifulSoup CSS-Selector Specific DOM Validation
# ---------------------------------------------------------------------------


class TestDOMStructureSelectors:
    """Uses precise CSS selectors to verify layout structure including Threat Intelligence sections."""

    def test_dom_tree_elements_with_css_selectors(
        self,
        real_template_dir: Path,
        populated_statistics: GeneralStatistics,
        sample_finding: ThreatFinding,
        tmp_path: Path,
    ):
        pcap_file = tmp_path / "selector_test.pcap"
        pcap_file.touch()

        mock_ioc_result = NormalizedIOCResult(
            source="VirusTotal",
            ip="8.8.8.8",
            is_malicious=True,
            raw_score=7,
            categories=("botnet",),
            confidence=0.90,
            last_seen=None,
            queried_at=FIXED_TEST_NOW,
            provider_error_code=None,
            provider_error_message=None,
        )

        threat_intel = {"8.8.8.8": [mock_ioc_result]}

        reporter = r.Reporter(template_dir=real_template_dir)
        output_file = reporter.generate(
            statistics=populated_statistics,
            findings=[sample_finding],
            threat_intel=threat_intel,
            source_file=pcap_file,
            analysis_duration=1.0,
        )

        soup = BeautifulSoup(output_file.read_text(encoding="utf-8"), "html.parser")

        # 1. Verify Main Container and Header Elements
        assert soup.select_one("html") is not None
        assert soup.select_one("body") is not None

        # 2. Verify Risk Summary Banner or Severity Cards
        risk_elements = soup.select(".risk-banner, .risk-score, .summary-card, .severity-badge, .badge")
        assert len(risk_elements) > 0, "Risk summary banner or severity badges missing in DOM"

        # 3. Verify Tables Structure (expects tables for findings/statistics/TI)
        tables = soup.select("table")
        assert len(tables) >= 1, "Expected at least one table for findings/statistics in DOM"

        # 4. Verify Chart Containers
        chart_elements = soup.select(".chart-container, .chart-card, img, .chart")
        assert len(chart_elements) >= 1, "Expected chart containers or images in DOM"

        # 5. Verify Threat Intelligence DOM Elements
        ti_elements = soup.select(".ti-card, .ti-source, .ti-malicious, .ti-score, .threat-intel, table")
        assert len(ti_elements) > 0, "Threat Intelligence elements missing in DOM"

        # 6. Verify Footer Element
        footer = soup.select_one("footer")
        if footer:
            assert len(footer.get_text(strip=True)) > 0


# ---------------------------------------------------------------------------
# 6. Snapshot Regression & Chart Builder Exceptions
# ---------------------------------------------------------------------------


class TestSnapshotAndChartExceptions:
    """Tests baseline snapshot and chart exception handling."""

    @staticmethod
    def normalize_html_for_snapshot(html: str) -> str:
        # Base64 grafikleri sabitle
        html = re.sub(
            r'data:image/[^;]+;base64,[A-Za-z0-9+/=]+',
            'data:image/png;base64,SNAPSHOT_BASE64_PLACEHOLDER',
            html,
        )

        # Tarih/saatleri sabitle
        html = re.sub(
            r'(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?)|(\d{2}\.\d{2}\.\d{4}\s+\d{2}:\d{2}:\d{2})',
            '2026-01-01 00:00:00',
            html,
        )

        # Süreleri sabitle
        html = re.sub(
            r'\d+\.\d+\s*s(aniye|econ|d)?',
            '0.00s',
            html,
        )

        # Boşlukları ve girintileri normalize et
        lines = [line.strip() for line in html.splitlines() if line.strip()]
        return "\n".join(lines)

    def test_snapshot_matches_baseline(
        self,
        real_template_dir: Path,
        populated_statistics: GeneralStatistics,
        sample_finding: ThreatFinding,
        tmp_path: Path,
    ):
        pcap_file = tmp_path / "snapshot.pcap"
        pcap_file.touch()

        reporter = r.Reporter(template_dir=real_template_dir)
        output_file = reporter.generate(
            statistics=populated_statistics,
            findings=[sample_finding],
            threat_intel={},
            source_file=pcap_file,
            analysis_duration=1.23,
        )

        rendered_html = output_file.read_text(encoding="utf-8")
        normalized_actual = self.normalize_html_for_snapshot(rendered_html)

        snapshot_file = Path(__file__).parent / "snapshots" / "report_snapshot.html"

        if not snapshot_file.exists():
            raise FileNotFoundError(
                f"Snapshot baseline missing at '{snapshot_file}'. "
                "Commit an initial baseline file explicitly for CI/CD pipeline runs."
            )

        # Şablon bilinçli olarak değiştirildiğinde baseline'ı elle düzenlemek
        # hataya açık (419 satırlık diff). UPDATE_SNAPSHOT=1 ile yeniden üretilir:
        #     UPDATE_SNAPSHOT=1 pytest tests/test_reporter.py -k snapshot
        # Ardından üretilen diff MUTLAKA gözden geçirilmelidir: bu kaçış yolu
        # snapshot testini "her zaman geçer" hale getirmek için değil, kasıtlı
        # değişiklikleri işlemek içindir.
        if os.getenv("UPDATE_SNAPSHOT") == "1":
            snapshot_file.write_text(normalized_actual + "\n", encoding="utf-8")
            pytest.skip(f"Snapshot yeniden üretildi: {snapshot_file}")

        expected_snapshot = snapshot_file.read_text(encoding="utf-8").strip()
        assert normalized_actual == expected_snapshot

    def test_chart_builder_exception_handling(
        self,
        real_template_dir: Path,
        populated_statistics: GeneralStatistics,
        tmp_path: Path,
    ):
        """Tests behavior when chart builder encounters an unhandled RuntimeError during execution."""
        reporter = r.Reporter(template_dir=real_template_dir)
        pcap_file = tmp_path / "test.pcap"
        pcap_file.touch()

        with patch.object(r.ChartBuilder, "_to_base64", side_effect=RuntimeError("Graphics Error")):
            with pytest.raises(RuntimeError) as exc_info:
                reporter.generate(
                    statistics=populated_statistics,
                    findings=[],
                    threat_intel={},
                    source_file=pcap_file,
                    analysis_duration=1.0,
                )

            assert "Graphics Error" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 7. Pipeline Integration & Generation Execution Tests
# ---------------------------------------------------------------------------


class TestPipelineIntegration:
    """Pipeline integration test executing Reporter end-to-end for threat, clean, and threat intel reports."""

    def test_full_reporting_pipeline_execution_with_threats(
        self, real_template_dir: Path, tmp_path: Path
    ):
        """Executes reporter pipeline end-to-end with threat findings."""
        pcap_source = tmp_path / "sample_analysis.pcap"
        pcap_source.write_bytes(b"MOCK_PCAP_DATA_BYTES")

        stats = GeneralStatistics(
            total_packets=5000,
            total_bytes=5242880,
            first_packet_time=1609459200.0,
            last_packet_time=1609459260.0,
            capture_duration=60.0,
            protocol_distribution={"TCP": 4000, "UDP": 1000},
            network_protocol_distribution={"IPv4": 5000},
            transport_protocol_distribution={"TCP": 4000, "UDP": 1000},
            application_protocol_distribution={"HTTPS": 4000},
            top_bandwidth_hosts=[("192.168.1.100", 1048576)],
            top_source_ips=[("192.168.1.100", 2500)],
            top_destination_ips=[("10.0.0.1", 2500)],
            top_tcp_ports=[(443, 3000)],
            top_udp_ports=[(53, 1000)],
            timeline={1609459200.0: 500},
        )

        findings = [
            ThreatFinding(
                rule_id="RULE-SCAN-01",
                title="Port Scan Activity",
                severity=ThreatSeverity.MEDIUM,
                description="Multiple connection attempts detected",
                evidence={"pattern": "SYN scan pattern", "packets": 150},
                source="192.168.1.100",
                destination="192.168.1.1",
                timestamp=FIXED_TEST_NOW,
            )
        ]

        reporter = r.Reporter(template_dir=real_template_dir)
        output_report = reporter.generate(
            statistics=stats,
            findings=findings,
            threat_intel={},
            source_file=pcap_source,
            analysis_duration=0.85,
        )

        assert output_report.exists()
        assert output_report.stat().st_size > 0

        html_content = output_report.read_text(encoding="utf-8")
        assert "Port Scan Activity" in html_content
        assert "192.168.1.100" in html_content

    def test_clean_report_pipeline_execution(
        self, real_template_dir: Path, tmp_path: Path, populated_statistics: GeneralStatistics
    ):
        """Executes reporter pipeline end-to-end with 0 findings (Clean Report)."""
        pcap_source = tmp_path / "clean_analysis.pcap"
        pcap_source.touch()

        reporter = r.Reporter(template_dir=real_template_dir)
        output_report = reporter.generate(
            statistics=populated_statistics,
            findings=[],
            threat_intel={},
            source_file=pcap_source,
            analysis_duration=0.50,
        )

        assert output_report.exists()
        assert output_report.stat().st_size > 0

        html_content = output_report.read_text(encoding="utf-8")
        assert "TEMİZ" in html_content or "Clean" in html_content or "0" in html_content

    def test_threat_intel_pipeline_integration(
        self, real_template_dir: Path, tmp_path: Path, populated_statistics: GeneralStatistics
    ):
        """Verifies complete Jinja2 rendering of Threat Intelligence results in the report."""
        pcap_source = tmp_path / "threat_intel.pcap"
        pcap_source.touch()

        mock_ioc_result = NormalizedIOCResult(
            source="VirusTotal",
            ip="8.8.8.8",
            is_malicious=True,
            raw_score=7,
            categories=("botnet",),
            confidence=0.90,
            last_seen=None,
            queried_at=FIXED_TEST_NOW,
            provider_error_code=None,
            provider_error_message=None,
        )

        threat_intel = {
            "8.8.8.8": [mock_ioc_result]
        }

        reporter = r.Reporter(template_dir=real_template_dir)
        output_report = reporter.generate(
            statistics=populated_statistics,
            findings=[],
            threat_intel=threat_intel,
            source_file=pcap_source,
            analysis_duration=1.0,
        )

        assert output_report.exists()
        html = output_report.read_text(encoding="utf-8")

        # Strict validation of Threat Intel rendering
        assert "Threat Intelligence Sonuçları" in html or "IOC Enrichment Sonuçları" in html
        assert "8.8.8.8" in html
        assert "VirusTotal" in html
        assert "EVET" in html or "Evet" in html
        assert "90%" in html
        assert "botnet" in html
        assert "7" in html


# ---------------------------------------------------------------------------
# 9. Sürüm Tutarlılığı
# ---------------------------------------------------------------------------


def test_tool_version_is_consistent_across_project():
    """Rapordaki araç sürümü, config ve pyproject ile aynı olmalı.

    Regresyon: bir zamanlar üç ayrı yerde üç FARKLI sürüm vardı
    (main.py banner "1.1.0-refactored", pyproject "1.2.0",
    reporter "1.2.0-forensic"). Rapordaki "Araç Sürümü" adli bir belgenin
    parçası olduğu için hangi sürümün üretildiği tek anlamlı olmalıdır.
    """
    import tomllib

    import config

    assert r._TOOL_VERSION == config.TOOL_VERSION

    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    with pyproject.open("rb") as fh:
        declared = tomllib.load(fh)["project"]["version"]

    assert declared == config.TOOL_VERSION, (
        f"pyproject.toml sürümü ({declared}) config.TOOL_VERSION ile "
        f"({config.TOOL_VERSION}) uyuşmuyor."
    )


def test_reports_are_written_under_configured_reports_dir(
    real_template_dir: Path, tmp_path: Path, populated_statistics: GeneralStatistics,
    isolated_reports_dir: Path,
):
    """Rapor DAİMA config.REPORTS_DIR altına yazılmalı.

    Regresyon: testler pcap'i tmp_path'te üretiyor ama Reporter çıktıyı
    projenin gerçek reports/ dizinine yazıyordu; her pytest koşusu depoya
    artefakt bırakıyordu (bkz. isolated_reports_dir fixture'ı).
    """
    pcap_source = tmp_path / "malicious" / "izolasyon.pcap"
    pcap_source.parent.mkdir(parents=True, exist_ok=True)
    pcap_source.write_bytes(b"\xd4\xc3\xb2\xa1")

    reporter = r.Reporter(template_dir=real_template_dir)
    output_report = reporter.generate(
        statistics=populated_statistics,
        findings=[],
        threat_intel={},
        source_file=pcap_source,
        analysis_duration=1.0,
    )

    assert output_report == isolated_reports_dir / "malicious" / "izolasyon_report.html"
    assert output_report.is_relative_to(tmp_path)


def test_finding_without_destination_renders_dash_not_none(
    real_template_dir: Path, tmp_path: Path, populated_statistics: GeneralStatistics
):
    """Hedefi olmayan bulgular tabloda "-" göstermeli, "None" değil.

    Regresyon: Jinja2'nin `default()` filtresi yalnızca değişken TANIMSIZ
    olduğunda devreye girer. `destination` alanı tanımlı ama None olan
    bulgularda (DNS tünelleme, DGA, uzun alan adı — tekil bir hedef IP'leri
    yoktur) şablon hücreye düz "None" yazıyordu.
    """
    finding = ThreatFinding(
        rule_id="SEC-DGA-001",
        title="Şüpheli DGA Alan Adı Tespiti",
        severity=ThreatSeverity.HIGH,
        description="Yüksek entropili alan adları tespit edildi.",
        evidence={"total_dga_domains": 3},
        source="VARIOUS",
        destination=None,
        timestamp=1609459200.0,
    )
    pcap_source = tmp_path / "dga.pcap"
    pcap_source.write_bytes(b"\xd4\xc3\xb2\xa1")

    reporter = r.Reporter(template_dir=real_template_dir)
    html = reporter.generate(
        statistics=populated_statistics,
        findings=[finding],
        threat_intel={},
        source_file=pcap_source,
        analysis_duration=1.0,
    ).read_text(encoding="utf-8")

    assert ">None<" not in html
    soup = BeautifulSoup(html, "html.parser")
    row = soup.select_one("table tbody tr:has(td)")
    cells = [td.get_text(strip=True) for td in soup.find_all("td")]
    assert "-" in cells
    assert "None" not in cells
    assert row is not None


def test_list_evidence_is_not_rendered_as_python_repr(
    real_template_dir: Path, tmp_path: Path, populated_statistics: GeneralStatistics
):
    """Liste tipindeki kanıtlar ham Python repr'ı olarak basılmamalı.

    Regresyon: şablon `{{ val }}` ile listeyi doğrudan bastığı için
    SEC-DGA-001 / SEC-LONG-DOMAIN-001 bulgularının "Kanıt" hücresinde
    `[{'domain': '...', 'length': 72, 'src_ip': '10.0.0.66',
    'timestamp': 1772355840.0}, ...]` şeklinde süslü parantezli, tırnaklı ve
    ham epoch'lu bir blok görünüyordu.
    """
    finding = ThreatFinding(
        rule_id="SEC-DGA-001",
        title="Şüpheli DGA Alan Adı Tespiti",
        severity=ThreatSeverity.HIGH,
        description="Yüksek entropili alan adları.",
        evidence={
            "total_dga_domains": 2,
            "domains": [
                {
                    "domain": "xk3n9vq2mz.example.com",
                    "label": "xk3n9vq2mz",
                    "entropy": 3.9,
                    "src_ip": "10.0.0.66",
                    "timestamp": 1609459200.0,
                },
                {
                    "domain": "qp7wt4bz1r.example.com",
                    "label": "qp7wt4bz1r",
                    "entropy": 4.1,
                    "src_ip": "10.0.0.66",
                    "timestamp": 1609459260.0,
                },
            ],
            "sampled_ports": [21, 22, 443],
        },
        source="VARIOUS",
        destination=None,
        timestamp=1609459200.0,
    )
    pcap_source = tmp_path / "dga_evidence.pcap"
    pcap_source.write_bytes(b"\xd4\xc3\xb2\xa1")

    reporter = r.Reporter(template_dir=real_template_dir)
    html = reporter.generate(
        statistics=populated_statistics,
        findings=[finding],
        threat_intel={},
        source_file=pcap_source,
        analysis_duration=1.0,
    ).read_text(encoding="utf-8")

    # Python repr'ının imzaları hiç görünmemeli.
    for artifact in ("{'domain'", "'src_ip':", "'entropy':", "[{", "}]"):
        assert artifact not in html, f"ham Python repr sızdı: {artifact}"

    # Veri KAYBOLMAMALI: alan adları ve okunabilir etiketler yerinde olmalı.
    assert "xk3n9vq2mz.example.com" in html
    assert "qp7wt4bz1r.example.com" in html
    assert "Alan Adı:" in html
    assert "Entropi:" in html
    # Kayıt içindeki epoch, diğer kanıt zamanlarıyla aynı biçime çevrilmeli.
    assert "2021-01-01 00:00:00 UTC" in html
    # Skaler liste de köşeli parantezsiz görünmeli.
    assert "[21, 22, 443]" not in html


def test_format_evidence_value_shapes():
    """_format_evidence_value: liste/sözlük/skaler davranışları."""
    assert r._format_evidence_value(42) == 42
    assert r._format_evidence_value("metin") == "metin"
    assert r._format_evidence_value([]) == "-"
    assert r._format_evidence_value(["a", "b"]) == "a\nb"
    assert r._format_evidence_value((21, 22)) == "21\n22"

    rendered = r._format_evidence_value([{"domain": "a.com", "timestamp": 1609459200.0}])
    assert rendered == "Alan Adı: a.com · Zaman: 2021-01-01 00:00:00 UTC"


class TestProtocolDistributionChart:
    """Protokol dağılımı grafiğinin uzun kuyruğu görünür kılması."""

    def test_uses_log_scale_when_one_protocol_dominates(self):
        """Ezici üstünlük durumunda x ekseni logaritmik olmalı.

        Regresyon: grafik pasta idi. Ölçülen gerçek bir capture'da 233.136 TLS
        paketine karşılık 26 NTP paketi vardı (9000:1); pastada bu, %98,4'lük
        tek bir daire ve gözle görülemeyen dilimler demekti. Adli analizde
        ilginç olan genellikle ezici çoğunluk değil, tam da o uzun kuyruktur.
        """
        builder = r.ChartBuilder()
        img, table = builder.protocol_distribution_chart(
            {"TLS": 233136, "QUIC": 3353, "DNS": 328, "NTP": 26}
        )

        assert isinstance(img, str) and img
        # En küçük protokol de tabloda gerçek sayısıyla durmalı.
        assert [row.label for row in table] == ["TLS", "QUIC", "DNS", "NTP"]
        assert table[0].value == "233,136 (98.4%)"
        assert table[-1].value.startswith("26 (")

        ratio = 233136 / 26
        assert ratio >= builder._LOG_SCALE_RATIO_THRESHOLD

    def test_uses_linear_scale_when_distribution_is_balanced(self):
        """Dengeli dağılımda logaritmik ölçek yanıltıcı olur, doğrusal kalmalı."""
        builder = r.ChartBuilder()
        distribution = {"TCP": 1000, "UDP": 800, "ICMP": 300, "ARP": 60}
        img, table = builder.protocol_distribution_chart(distribution)

        assert isinstance(img, str) and img
        assert len(table) == 4
        assert max(distribution.values()) / min(distribution.values()) < (
            builder._LOG_SCALE_RATIO_THRESHOLD
        )

    def test_table_rows_carry_count_and_percentage(self):
        """Tablo hem ham sayıyı hem yüzdeyi taşımalı.

        Yüzdeler eskiden yalnızca pasta legend'indeydi; pasta kaldırıldığı için
        bu bilginin tabloya taşınmış olması gerekir.
        """
        _img, table = r.ChartBuilder().protocol_distribution_chart({"TCP": 75, "UDP": 25})
        assert [(row.label, row.value) for row in table] == [
            ("TCP", "75 (75.0%)"),
            ("UDP", "25 (25.0%)"),
        ]

    def test_empty_distribution_returns_no_chart(self):
        img, table = r.ChartBuilder().protocol_distribution_chart({})
        assert img is None
        assert table == []


class TestLayeredProtocolChart:
    """Katman bazlı protokol grafiği (ağ / taşıma / uygulama)."""

    # Gerçek bir capture'dan (236.843 paket) alınmış katman dağılımları.
    REAL_NETWORK: ClassVar[dict[str, int]] = {"IPv4": 236843}
    REAL_TRANSPORT: ClassVar[dict[str, int]] = {"TCP": 233136, "UDP": 3707}
    REAL_APPLICATION: ClassVar[dict[str, int]] = {
        "TLS": 233136, "QUIC": 3353, "DNS": 328, "NTP": 26,
    }

    def test_every_layer_and_protocol_appears_once(self):
        """Üç katmanın her protokolü, katman adıyla etiketli tek satır üretmeli."""
        img, table = r.ChartBuilder().layered_protocol_chart(
            self.REAL_NETWORK, self.REAL_TRANSPORT, self.REAL_APPLICATION
        )

        assert isinstance(img, str) and img
        labels = [row.label for row in table]
        assert labels == [
            "Ağ · IPv4",
            "Taşıma · TCP",
            "Taşıma · UDP",
            "Uygulama · TLS",
            "Uygulama · QUIC",
            "Uygulama · DNS",
            "Uygulama · NTP",
        ]
        # Katmanlar birbirinden bağımsız yüzdelenmeli (her katman kendi içinde %100).
        assert table[0].value == "236,843 (100.0%)"
        assert table[1].value == "233,136 (98.4%)"
        assert table[-1].value.startswith("26 (")

    def test_layers_are_independent_of_top_layer_collapsing(self):
        """Katman grafiği, birleşik grafiğin gizlediği bilgiyi göstermeli.

        protocol_distribution_chart her paketi yalnızca EN ÜST katmanıyla
        sayar; 233.136 TLS paketinin aynı zamanda TCP paketi olduğu orada
        görünmez. Bu grafik ikisini de ayrı ayrı göstermek zorundadır.
        """
        _img, table = r.ChartBuilder().layered_protocol_chart(
            self.REAL_NETWORK, self.REAL_TRANSPORT, self.REAL_APPLICATION
        )
        values = {row.label: row.value for row in table}

        assert values["Taşıma · TCP"].startswith("233,136")
        assert values["Uygulama · TLS"].startswith("233,136")

    def test_unknown_key_is_displayed_readably_not_dropped(self):
        """"UNKNOWN" satırı okunur bir etikete çevrilmeli ama ASLA atılmamalı.

        "Uygulama protokolü belirlenemeyen paket sayısı" başlı başına bir
        bulgudur: tanınmayan veya özel protokoller orada saklanır.
        """
        _img, table = r.ChartBuilder().layered_protocol_chart(
            {"IPv4": 364},
            {"ICMP": 150, "UDP": 137, "TCP": 77},
            {"UNKNOWN": 166, "DNS": 126, "TLS": 72},
        )
        labels = [row.label for row in table]

        assert "Uygulama · Belirlenemedi" in labels
        assert "Uygulama · UNKNOWN" not in labels
        row = next(r_ for r_ in table if r_.label == "Uygulama · Belirlenemedi")
        assert row.value.startswith("166 (")

    def test_missing_layer_is_skipped_not_crashed(self):
        """Bir katman boşsa grafik yine üretilmeli, o katman atlanmalı."""
        img, table = r.ChartBuilder().layered_protocol_chart(
            {"IPv4": 10}, {}, {"DNS": 10}
        )
        assert isinstance(img, str) and img
        assert [row.label for row in table] == ["Ağ · IPv4", "Uygulama · DNS"]

    def test_all_layers_empty_returns_no_chart(self):
        assert r.ChartBuilder().layered_protocol_chart({}, {}, {}) == (None, [])

    def test_chart_section_is_wired_into_report(self, populated_statistics: GeneralStatistics):
        """Grafik, protokol dağılımının hemen ardında rapora girmeli."""
        charts = r.Reporter()._build_charts_list(populated_statistics)
        ids = [c.id for c in charts]

        assert ids.index("layered_protocol_distribution") == ids.index("protocol_distribution") + 1
        assert len(charts) == 7


class TestRiskBarAndLevelConsistency:
    """Risk seviyesi etiketi ile ilerleme çubuğu asla çelişmemeli."""

    # (etiket -> çubuğun izin verilen aralığı). Bantlar çubuğu dörde böler.
    LEVEL_BANDS: ClassVar[dict[str, tuple[int, int]]] = {
        "TEMİZ": (0, 0),
        "DÜŞÜK": (1, 25),
        "ORTA": (25, 50),
        "YÜKSEK": (50, 75),
        "KRİTİK": (75, 100),
    }

    @staticmethod
    def _findings(**counts: int) -> list[ThreatFinding]:
        out: list[ThreatFinding] = []
        for name, n in counts.items():
            severity = ThreatSeverity[name.upper()]
            out.extend(
                ThreatFinding(f"R-{name}-{i}", "t", severity, "d", {}, "src")
                for i in range(n)
            )
        return out

    def test_single_low_finding_is_not_reported_as_clean(self):
        """1-3 puanlık skorlar "TEMİZ" DEĞİL "DÜŞÜK" olmalı.

        Regresyon: DÜŞÜK eşiği 4'tü, dolayısıyla 1, 2 veya 3 adet LOW bulgu
        hiçbir eşiği karşılamıyor ve "TEMİZ" kovasına düşüyordu. Rapor, bulgu
        tablosunda gerçek bulguları listelerken en üstte "Risk Seviyesi:
        TEMİZ" yazıyordu. Adli bir raporda hatanın bu yönü -- var olan bulguyu
        yok saymak -- en tehlikelisidir.
        """
        for count in (1, 2, 3):
            summary = r.compute_risk_summary(self._findings(low=count))
            assert summary.risk_score == count
            assert summary.total_findings == count
            assert summary.risk_level == "DÜŞÜK", (
                f"{count} adet LOW bulgu '{summary.risk_level}' olarak raporlandı"
            )

    def test_clean_is_reserved_for_zero_weight(self):
        """"TEMİZ" yalnızca ağırlıklı skor 0 iken görünmeli."""
        assert r.compute_risk_summary([]).risk_level == "TEMİZ"
        # INFO'nun ağırlığı 0'dır (bilgilendirme, tehdit değil).
        assert r.compute_risk_summary(self._findings(info=5)).risk_level == "TEMİZ"

    @pytest.mark.parametrize(
        "counts",
        [
            {"low": 1}, {"low": 4}, {"medium": 1}, {"medium": 2, "low": 4},
            {"high": 1}, {"high": 1, "medium": 2, "low": 4},
            {"critical": 1}, {"critical": 2},
            {"critical": 1, "high": 4, "medium": 1, "low": 1},
            {"high": 20}, {"critical": 100},
        ],
    )
    def test_bar_position_always_matches_its_level_band(self, counts):
        """Çubuğun doluluğu, etiketin bandının dışına ASLA çıkmamalı.

        Regresyon: çubuk `min(skor, 100)` idi. Tek bir CRITICAL bulgu 30 puan
        eder; rapor "KRİTİK" yazarken çubuk %30 dolu, yani gözle "düşük risk"
        görünüyordu. Ters uçta 20 HIGH (300) ile 100 CRITICAL (3000) çubukta
        ayırt edilemiyor, ikisi de %100'e kırpılıyordu.
        """
        summary = r.compute_risk_summary(self._findings(**counts))
        low, high = self.LEVEL_BANDS[summary.risk_level]

        assert low <= summary.risk_score_normalized <= high, (
            f"skor={summary.risk_score} seviye={summary.risk_level} "
            f"çubuk=%{summary.risk_score_normalized} bandın ({low}-{high}) dışında"
        )

    def test_bar_never_exceeds_container_width(self):
        """Sınırsız skor, çubuğu kapsayıcısından taşırmamalı."""
        summary = r.compute_risk_summary(self._findings(critical=1000))
        assert summary.risk_score == 30000
        assert summary.risk_score_normalized == r._RISK_SCORE_DISPLAY_MAX

    def test_bar_is_monotonic_in_score(self):
        """Skor arttıkça çubuk asla geri gitmemeli."""
        positions = [
            r._compute_risk_bar_position(score)
            for score in range(0, 400)
        ]
        assert positions == sorted(positions)
        assert positions[0] == 0


class TestThreatIntelConsensus:
    """Sağlayıcı uzlaşısı: "hüküm veremedi" ASLA "temiz" sayılmamalı."""

    @staticmethod
    def _result(source: str, is_malicious: bool | None, error: str | None = None):
        return NormalizedIOCResult(
            source=source,
            ip="9.9.9.9",
            is_malicious=is_malicious,
            raw_score=0 if is_malicious is not None else None,
            categories=(),
            last_seen=None,
            queried_at=FIXED_TEST_NOW,
            provider_error_code=None,
            provider_error_message=error,
            confidence=None,
        )

    def _summarize(self, *results):
        summaries = r._prepare_threat_intel_for_template({"9.9.9.9": list(results)})
        assert len(summaries) == 1
        return summaries[0]

    def test_partial_answers_are_not_reported_as_clean(self):
        """1 temiz + 2 hata "TEMİZ" DEĞİL "KISMİ TEMİZ" olmalı.

        Regresyon: şablon `{% elif clean_count > 0 %} CONSENSUS: CLEAN`
        diyordu. Üç sağlayıcıdan ikisi zaman aşımına uğrayıp yalnızca biri
        "temiz" dediğinde rapor "0 / 3 sağlayıcı zararlı dedi — CONSENSUS:
        CLEAN" yazıyordu; oysa uzlaşı diye bir şey yoktu, iki sağlayıcı hiç oy
        kullanamamıştı. Bir IOC'yi yanlışlıkla temiz göstermek adli bir
        raporda yapılabilecek en zararlı hatadır.
        """
        summary = self._summarize(
            self._result("VirusTotal", False),
            self._result("AbuseIPDB", None, "timeout"),
            self._result("AlienVault OTX", None, "HTTP 500"),
        )

        assert summary.consensus_label == "KISMİ TEMİZ"
        assert summary.consensus_label != "TEMİZ"
        assert summary.answered_providers == 1
        assert summary.total_providers == 3
        # Payda toplam sağlayıcı değil, YANIT VEREN sağlayıcı olmalı.
        assert summary.malicious_providers == 0
        assert "eksiktir" in summary.consensus_detail

    def test_all_providers_answered_and_clean(self):
        summary = self._summarize(
            self._result("VirusTotal", False),
            self._result("AbuseIPDB", False),
            self._result("AlienVault OTX", False),
        )
        assert summary.consensus_label == "TEMİZ"
        assert summary.answered_providers == summary.total_providers == 3

    def test_all_providers_malicious(self):
        summary = self._summarize(
            self._result("VirusTotal", True),
            self._result("AbuseIPDB", True),
        )
        assert summary.consensus_label == "ZARARLI"
        assert summary.consensus_class == "CRITICAL"
        assert summary.malicious_providers == 2

    def test_disagreement_is_flagged_as_conflicting(self):
        summary = self._summarize(
            self._result("VirusTotal", True),
            self._result("AbuseIPDB", False),
            self._result("AlienVault OTX", None, "timeout"),
        )
        assert summary.consensus_label == "ÇELİŞKİLİ"
        assert summary.answered_providers == 2
        assert summary.malicious_providers == 1

    def test_no_provider_could_answer(self):
        summary = self._summarize(
            self._result("VirusTotal", None, "timeout"),
            self._result("AbuseIPDB", None, "HTTP 401"),
        )
        assert summary.consensus_label == "VERİ YOK"
        assert summary.answered_providers == 0
        assert summary.malicious_providers == 0

    def test_malicious_verdict_survives_unanswered_providers(self):
        """Tek bir sağlayıcı bile zararlı dediyse bu asla gizlenmemeli."""
        summary = self._summarize(
            self._result("VirusTotal", True),
            self._result("AbuseIPDB", None, "timeout"),
            self._result("AlienVault OTX", None, "timeout"),
        )
        assert summary.consensus_label == "ZARARLI"
        assert summary.consensus_class == "CRITICAL"

    def test_rendered_report_never_claims_clean_on_partial_data(
        self, real_template_dir: Path, tmp_path: Path, populated_statistics: GeneralStatistics
    ):
        """Uçtan uca: kısmi veride rapor HTML'i "temiz" iddiasında bulunmamalı."""
        pcap_source = tmp_path / "partial_ti.pcap"
        pcap_source.write_bytes(b"\xd4\xc3\xb2\xa1")

        html = r.Reporter(template_dir=real_template_dir).generate(
            statistics=populated_statistics,
            findings=[],
            threat_intel={
                "9.9.9.9": [
                    self._result("VirusTotal", False),
                    self._result("AbuseIPDB", None, "timeout"),
                    self._result("AlienVault OTX", None, "HTTP 500"),
                ]
            },
            source_file=pcap_source,
            analysis_duration=1.0,
        ).read_text(encoding="utf-8")

        assert "KISMİ TEMİZ" in html
        assert "CONSENSUS: CLEAN" not in html
        assert "2 yanıtsız" in html


def test_empty_threat_intel_state_does_not_imply_clean(
    real_template_dir: Path, tmp_path: Path, populated_statistics: GeneralStatistics
):
    """Boş TI bölümü "kontrol edildi, temiz" gibi okunmamalı.

    "Threat Intelligence sonucu bulunmamaktadır." ifadesi, zenginleştirmenin
    hiç çalışmamış olmasıyla çalışıp bir şey bulamamış olmasını birbirine
    karıştırıyordu.
    """
    pcap_source = tmp_path / "no_ti.pcap"
    pcap_source.write_bytes(b"\xd4\xc3\xb2\xa1")

    html = r.Reporter(template_dir=real_template_dir).generate(
        statistics=populated_statistics,
        findings=[],
        threat_intel={},
        source_file=pcap_source,
        analysis_duration=1.0,
    ).read_text(encoding="utf-8")

    assert "çalıştırılmadı" in html
    assert "temiz olduğu anlamına GELMEZ" in html


def test_report_declares_viewport_for_responsive_css(
    real_template_dir: Path, tmp_path: Path, populated_statistics: GeneralStatistics
):
    """Duyarlı CSS'in mobilde çalışabilmesi için viewport meta'sı şart.

    Regresyon: şablonda `@media (max-width: 900px)` kuralları vardı ama
    viewport meta'sı yoktu; mobil tarayıcılar ~980px'lik sanal viewport
    kullandığı için o kurallar telefonda hiç tetiklenmiyor, yazılmış düzen
    ölü kod oluyordu.
    """
    pcap_source = tmp_path / "viewport.pcap"
    pcap_source.write_bytes(b"\xd4\xc3\xb2\xa1")

    html = r.Reporter(template_dir=real_template_dir).generate(
        statistics=populated_statistics,
        findings=[],
        threat_intel={},
        source_file=pcap_source,
        analysis_duration=1.0,
    ).read_text(encoding="utf-8")

    soup = BeautifulSoup(html, "html.parser")
    viewport = soup.find("meta", attrs={"name": "viewport"})
    assert viewport is not None, "viewport meta'sı yok, responsive CSS mobilde çalışmaz"
    assert "width=device-width" in viewport["content"]
    assert "max-width: 900px" in html

    # Erişilebilirlik: her th'nin scope'u olmalı (TI tablosunda eksikti).
    assert all(th.get("scope") for th in soup.find_all("th"))
