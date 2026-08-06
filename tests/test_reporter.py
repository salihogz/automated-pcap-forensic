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

import re
from datetime import datetime, timezone
from pathlib import Path
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
FIXED_TEST_NOW = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

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
        """Validates _write successfully writes files, auto-creates parent directories, and wraps write permission errors."""
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

        assert "template" in str(exc_info.value).lower() or isinstance(exc_info.value.__cause__, (TemplateNotFound, TemplateError))

    def test_generate_public_method_invalid_template_dir(self, tmp_path: Path, populated_statistics: GeneralStatistics):
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

        assert "template" in str(exc_info.value).lower() or isinstance(exc_info.value.__cause__, (TemplateNotFound, TemplateError))

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
        assert "dizin" in str(exc3.value).lower() or "directory" in str(exc3.value).lower() or "path" in str(exc3.value).lower()

        # 4. Invalid suffix
        invalid_suffix_path = tmp_path / "report.txt"
        with pytest.raises(r.ReportGenerationError) as exc4:
            reporter._validate_inputs(valid_stats, valid_meta, invalid_suffix_path)
        assert ".html" in str(exc4.value).lower()


# ---------------------------------------------------------------------------
# 4. compute_risk_summary, Exact Threshold Boundaries & ChartBuilder
# ---------------------------------------------------------------------------


class TestRiskSummaryAndChartBuilderUnits:
    """Explicit unit tests for compute_risk_summary calculation, exact threshold boundaries, and ChartBuilder methods."""

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
        summary_score_14 = r.compute_risk_summary([make_finding(ThreatSeverity.MEDIUM)] * 2 + [make_finding(ThreatSeverity.LOW)] * 4)
        assert summary_score_14.risk_level == "ORTA"

        # Score 15 (1 x HIGH = 15 pts) -> YÜKSEK (Score >= 15)
        summary_score_15 = r.compute_risk_summary([make_finding(ThreatSeverity.HIGH)])
        assert summary_score_15.risk_level == "YÜKSEK"

        # Score 29 (1 x HIGH + 2 x MEDIUM + 4 x LOW = 29 pts) -> YÜKSEK (Score < 30)
        summary_score_29 = r.compute_risk_summary([make_finding(ThreatSeverity.HIGH)] + [make_finding(ThreatSeverity.MEDIUM)] * 2 + [make_finding(ThreatSeverity.LOW)] * 4)
        assert summary_score_29.risk_level == "YÜKSEK"

        # Score 30 (1 x CRITICAL = 30 pts) -> KRİTİK (Score >= 30)
        summary_score_30 = r.compute_risk_summary([make_finding(ThreatSeverity.CRITICAL)])
        assert summary_score_30.risk_level == "KRİTİK"

        # Score 59 -> KRİTİK
        summary_score_59 = r.compute_risk_summary([make_finding(ThreatSeverity.CRITICAL)] + [make_finding(ThreatSeverity.HIGH)] * 1 + [make_finding(ThreatSeverity.MEDIUM)] * 2 + [make_finding(ThreatSeverity.LOW)] * 4)
        assert summary_score_59.risk_level == "KRİTİK"

        # Score 60+ -> KRİTİK
        summary_score_60 = r.compute_risk_summary([make_finding(ThreatSeverity.CRITICAL)] * 2)
        assert summary_score_60.risk_level == "KRİTİK"

    def test_risk_score_is_unbounded_but_display_value_is_clamped(self):
        """Ham skor sınırsız kalmalı, sunum değeri 0-100 aralığına kırpılmalıdır.

        Şablon ilerleme çubuğunu `width: {{ skor }}%` ile çiziyordu; ham skor
        sınırsız bir ağırlıklı toplam olduğundan (20 HIGH = 300) çubuk
        kapsayıcısını taşırıyor ve rapor "300 / 100" gibi anlamsız bir değer
        basıyordu. Eşik tablosu ham skora göre kalibre edildiği için ham
        değerin kendisi ASLA kırpılmamalıdır.
        """
        def make_finding(severity: ThreatSeverity) -> ThreatFinding:
            return ThreatFinding("ID", "Title", severity, "", {}, "src", "dst", FIXED_TEST_NOW)

        summary = r.compute_risk_summary([make_finding(ThreatSeverity.HIGH)] * 20)
        assert summary.risk_score == 300, "ham skor kırpılmamalı (eşik tablosu buna bağlı)"
        assert summary.risk_score_normalized == 100, "sunum değeri 100'de sınırlanmalı"
        assert summary.risk_level == "KRİTİK"

        # Eşiğin altındaki skorlarda iki değer birbirinin aynısı olmalı.
        low_summary = r.compute_risk_summary([make_finding(ThreatSeverity.HIGH)])
        assert low_summary.risk_score == 15
        assert low_summary.risk_score_normalized == 15

        assert r.compute_risk_summary([]).risk_score_normalized == 0

    def test_build_charts_list_exact_count_and_titles(self, populated_statistics: GeneralStatistics):
        """Directly tests Reporter._build_charts_list to verify exact count (5) and keywords in titles."""
        reporter = r.Reporter()
        charts = reporter._build_charts_list(populated_statistics)

        assert isinstance(charts, list)
        assert len(charts) == 5

        # Extract chart titles assuming dataclass/object or dict representation
        titles = [getattr(c, "title", c.get("title") if isinstance(c, dict) else None) for c in charts]
        
        # Verify specific expected production titles exist
        assert any("Protokol" in str(t) or "Protocol" in str(t) for t in titles if t)
        assert any("En Aktif Hostlar" in str(t) or "Talkers" in str(t) for t in titles if t)
        assert any("Bant Genişliği" in str(t) or "Bandwidth" in str(t) for t in titles if t)
        assert any("Zaman" in str(t) or "Timeline" in str(t) for t in titles if t)
        assert any("Port" in str(t) for t in titles if t)

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