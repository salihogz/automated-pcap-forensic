"""main.py (CLI giriş noktası / pipeline orkestrasyonu) testleri.

Bu dosya oluşturulmadan önce main.py'nin hiç testi yoktu: boru hattının tüm
aşamalarını birbirine bağlayan, hata yollarını belirleyen ve çıkış kodunu
üreten katman tamamen kapsam dışındaydı.

Testlerin çoğu boru hattı bileşenlerini mock'lar; amaç modüllerin kendi
davranışını (onların kendi test dosyaları var) değil, main()'in onları doğru
sırayla çağırıp doğru çıkış kodunu döndürmesini doğrulamaktır. Dosyanın
sonunda demo capture ile gerçek bir uçtan uca test bulunur.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import config
import main as main_module
from modules.models import GeneralStatistics

# ======================================================================
# _is_public_ip
# ======================================================================


@pytest.mark.parametrize(
    "ip",
    [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "2606:4700:4700::1111",
    ],
)
def test_is_public_ip_accepts_globally_routable_addresses(ip: str):
    assert main_module._is_public_ip(ip) is True


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",  # RFC1918
        "192.168.1.1",  # RFC1918
        "172.16.0.1",  # RFC1918
        "127.0.0.1",  # loopback
        "169.254.0.1",  # link-local
        "224.0.0.1",  # multicast (is_global True döner, ayrıca elenmeli)
        "224.0.0.251",  # mDNS
        "239.255.255.250",  # SSDP
        "ff02::fb",  # IPv6 mDNS
        "0.0.0.0",  # unspecified
        "::1",  # IPv6 loopback
        "fe80::1",  # IPv6 link-local
    ],
)
def test_is_public_ip_rejects_private_and_reserved_addresses(ip: str):
    """Private/rezerve aralıklar dış TI sağlayıcılarına hiç sorulmamalı.

    Bu bir optimizasyon değil doğruluk meselesi: bazı sağlayıcılar bu
    adresleri HTTP 400 ile reddediyor, bazıları ise "veri yok" durumunu
    raporda "temiz" gibi okunabilecek bir sonuca çeviriyor.
    """
    assert main_module._is_public_ip(ip) is False


@pytest.mark.parametrize("value", ["", "not-an-ip", "999.999.999.999", "10.0.0", "::gg"])
def test_is_public_ip_returns_false_for_unparseable_values(value: str):
    """Bozuk bir IP metni istisna fırlatmamalı, sadece sorgu dışı kalmalı."""
    assert main_module._is_public_ip(value) is False


# ======================================================================
# resolve_target_path
# ======================================================================


def _args(file: Path | None = None, verbose: bool = False) -> argparse.Namespace:
    return argparse.Namespace(file=file, verbose=verbose)


def test_resolve_target_path_returns_explicit_file_when_it_exists(tmp_path: Path):
    capture = tmp_path / "capture.pcapng"
    capture.touch()

    assert main_module.resolve_target_path(_args(file=capture)) == capture


def test_resolve_target_path_returns_none_for_missing_explicit_file(tmp_path: Path, caplog):
    missing = tmp_path / "yok.pcapng"

    with caplog.at_level(logging.ERROR):
        result = main_module.resolve_target_path(_args(file=missing))

    assert result is None
    assert "bulunamadı" in caplog.text


def test_resolve_target_path_searches_samples_recursively(tmp_path: Path, monkeypatch):
    """-f verilmediğinde alt klasörler de taranmalı (rglob).

    Örnek capture'lar samples/clean/ ve samples/malicious/ altında tutuluyor;
    düz bir glob bunları bulamaz ve araç "dosya yok" diye çıkardı.
    """
    (tmp_path / "malicious").mkdir()
    nested = tmp_path / "malicious" / "deep.pcapng"
    nested.touch()
    monkeypatch.setattr(config, "SAMPLES_DIR", tmp_path)

    assert main_module.resolve_target_path(_args()) == nested


def test_resolve_target_path_picks_first_in_sorted_order(tmp_path: Path, monkeypatch):
    """Seçim deterministik olmalı: aynı dizinde iki dosya varsa hep aynısı."""
    for name in ("b_second.pcap", "a_first.pcap", "c_third.pcapng"):
        (tmp_path / name).touch()
    monkeypatch.setattr(config, "SAMPLES_DIR", tmp_path)

    assert main_module.resolve_target_path(_args()).name == "a_first.pcap"


def test_resolve_target_path_returns_none_when_samples_dir_is_empty(tmp_path: Path, monkeypatch, caplog):
    monkeypatch.setattr(config, "SAMPLES_DIR", tmp_path)

    with caplog.at_level(logging.ERROR):
        result = main_module.resolve_target_path(_args())

    assert result is None
    assert "PCAP dosyası belirtin" in caplog.text


def test_resolve_target_path_ignores_unsupported_extensions(tmp_path: Path, monkeypatch):
    (tmp_path / "notes.txt").touch()
    (tmp_path / "archive.zip").touch()
    monkeypatch.setattr(config, "SAMPLES_DIR", tmp_path)

    assert main_module.resolve_target_path(_args()) is None


# ======================================================================
# parse_arguments / setup_logging / print_banner
# ======================================================================


def test_parse_arguments_reads_file_and_verbose_flags(monkeypatch):
    monkeypatch.setattr("sys.argv", ["main.py", "-f", "x.pcapng", "-v"])

    args = main_module.parse_arguments()

    assert args.file == Path("x.pcapng")
    assert args.verbose is True


def test_parse_arguments_defaults(monkeypatch):
    monkeypatch.setattr("sys.argv", ["main.py"])

    args = main_module.parse_arguments()

    assert args.file is None
    assert args.verbose is False


@pytest.mark.parametrize(("verbose", "expected"), [(True, logging.DEBUG), (False, logging.INFO)])
def test_setup_logging_sets_level_and_silences_scapy(tmp_path: Path, monkeypatch, verbose: bool, expected: int):
    monkeypatch.setattr(config, "LOGS_DIR", tmp_path)

    main_module.setup_logging(verbose=verbose)

    try:
        assert logging.getLogger().level == expected
        # Scapy'nin cipher-suite gürültüsü bastırılmalı.
        assert logging.getLogger("scapy").level == logging.ERROR
        assert (tmp_path / config.DEFAULT_LOG_NAME).exists()
    finally:
        # Diğer testlerin log yakalamasını bozmamak için handler'ları kapat.
        for handler in logging.getLogger().handlers[:]:
            handler.close()
            logging.getLogger().removeHandler(handler)


def test_print_banner_writes_tool_name(capsys):
    main_module.print_banner()

    assert "Automated PCAP Forensic Analysis Tool" in capsys.readouterr().out


# ======================================================================
# main() -- orkestrasyon
# ======================================================================


def _empty_stats() -> GeneralStatistics:
    return GeneralStatistics(0, 0, 0.0, 0.0, 0.0, {}, {}, {}, {}, [], [], [], [], [], {})


class _PipelinePatches:
    """main() içindeki tüm boru hattı bileşenlerini mock'layan yardımcı."""

    def __init__(self, packets=None, findings=None):
        self.packets = packets if packets is not None else []
        self.findings = findings if findings is not None else []
        self.reporter = MagicMock()
        self.reporter.generate.return_value = Path("reports/clean/x_report.html")
        self.service = MagicMock()
        self.service.enrich.return_value = []
        self._stack = []

    def __enter__(self):
        parser = MagicMock()
        parser.parse.return_value = self.packets
        detector = MagicMock()
        detector.detect.return_value = self.findings

        patches = [
            patch.object(main_module, "PCAPParser", return_value=parser),
            patch.object(main_module, "build_general_statistics", return_value=_empty_stats()),
            patch.object(main_module, "ThreatDetector", return_value=detector),
            patch.object(main_module, "Reporter", return_value=self.reporter),
            patch.object(main_module, "build_default_session", return_value=MagicMock()),
            patch.object(main_module, "build_default_providers", return_value=[]),
            patch.object(main_module, "ThreatIntelService", return_value=self.service),
        ]
        for p in patches:
            p.start()
            self._stack.append(p)
        return self

    def __exit__(self, *exc):
        for p in reversed(self._stack):
            p.stop()
        return False


def _packet(src_ip: str, dst_ip: str):
    packet = MagicMock()
    packet.src_ip = src_ip
    packet.dst_ip = dst_ip
    return packet


def test_main_returns_zero_and_generates_report_on_success(tmp_path: Path, monkeypatch):
    capture = tmp_path / "ok.pcapng"
    capture.touch()
    monkeypatch.setattr("sys.argv", ["main.py", "-f", str(capture)])
    monkeypatch.setattr(config, "LOGS_DIR", tmp_path)

    with _PipelinePatches() as pipeline:
        exit_code = main_module.main()

    assert exit_code == 0
    pipeline.reporter.generate.assert_called_once()
    assert pipeline.reporter.generate.call_args.kwargs["source_file"] == capture


def test_main_returns_one_when_no_target_file_resolved(tmp_path: Path, monkeypatch):
    """Hedef dosya çözülemediğinde boru hattına hiç girilmemeli."""
    monkeypatch.setattr("sys.argv", ["main.py", "-f", str(tmp_path / "yok.pcapng")])
    monkeypatch.setattr(config, "LOGS_DIR", tmp_path)

    with _PipelinePatches() as pipeline:
        exit_code = main_module.main()

    assert exit_code == 1
    pipeline.reporter.generate.assert_not_called()


def test_main_queries_only_public_ips_for_threat_intel(tmp_path: Path, monkeypatch):
    """TI zenginleştirmesi yalnızca genel IP'ler için çağrılmalı."""
    capture = tmp_path / "ok.pcapng"
    capture.touch()
    monkeypatch.setattr("sys.argv", ["main.py", "-f", str(capture)])
    monkeypatch.setattr(config, "LOGS_DIR", tmp_path)

    packets = [
        _packet("10.0.0.5", "8.8.8.8"),  # biri private, biri public
        _packet("192.168.1.1", "127.0.0.1"),  # ikisi de sorgu dışı
        _packet("1.1.1.1", None),  # None atlanmalı
    ]

    with _PipelinePatches(packets=packets) as pipeline:
        exit_code = main_module.main()

    assert exit_code == 0
    enriched = {call.args[0] for call in pipeline.service.enrich.call_args_list}
    assert enriched == {"8.8.8.8", "1.1.1.1"}


def test_main_skips_threat_intel_entirely_when_no_public_ips(tmp_path: Path, monkeypatch):
    capture = tmp_path / "ok.pcapng"
    capture.touch()
    monkeypatch.setattr("sys.argv", ["main.py", "-f", str(capture)])
    monkeypatch.setattr(config, "LOGS_DIR", tmp_path)

    packets = [_packet("10.0.0.5", "10.0.0.6")]

    with _PipelinePatches(packets=packets) as pipeline:
        exit_code = main_module.main()

    assert exit_code == 0
    pipeline.service.enrich.assert_not_called()


# NOT: Bu testlerde caplog yerine main_module.logger mock'lanıyor. Sebebi
# setup_logging()'in logging.basicConfig(..., force=True) çağırması: force=True
# kök logger'daki TÜM handler'ları kaldırır ve pytest'in caplog handler'ı da
# bunlara dahildir, dolayısıyla caplog main() içindeki hiçbir kaydı göremez.


@pytest.mark.parametrize("exc", [FileNotFoundError("yok"), ValueError("geçersiz"), RuntimeError("akış hatası")])
def test_main_returns_one_on_expected_pipeline_errors(tmp_path: Path, monkeypatch, exc: Exception):
    """Beklenen hata sınıfları çökme değil, 1 çıkış kodu üretmeli."""
    capture = tmp_path / "ok.pcapng"
    capture.touch()
    monkeypatch.setattr("sys.argv", ["main.py", "-f", str(capture)])
    monkeypatch.setattr(config, "LOGS_DIR", tmp_path)

    with _PipelinePatches():
        failing = MagicMock()
        failing.parse.side_effect = exc
        with (
            patch.object(main_module, "PCAPParser", return_value=failing),
            patch.object(main_module, "logger") as mock_logger,
        ):
            exit_code = main_module.main()

    assert exit_code == 1
    error_messages = " ".join(str(call) for call in mock_logger.error.call_args_list)
    assert "Analiz başarısız oldu" in error_messages
    # Traceback DEĞİL, tek satırlık hata mesajı beklenir: bunlar öngörülen
    # hata sınıfları, bir programlama hatası değil.
    mock_logger.exception.assert_not_called()


def test_main_returns_one_and_logs_traceback_on_unexpected_error(tmp_path: Path, monkeypatch):
    """Beklenmeyen istisnalar yutulmamalı: çıkış kodu 1 ve traceback loglanmalı."""
    capture = tmp_path / "ok.pcapng"
    capture.touch()
    monkeypatch.setattr("sys.argv", ["main.py", "-f", str(capture)])
    monkeypatch.setattr(config, "LOGS_DIR", tmp_path)

    with _PipelinePatches():
        broken = MagicMock()
        broken.parse.side_effect = TypeError("beklenmeyen")
        with (
            patch.object(main_module, "PCAPParser", return_value=broken),
            patch.object(main_module, "logger") as mock_logger,
        ):
            exit_code = main_module.main()

    assert exit_code == 1
    # logger.exception() traceback'i de kaydeder; beklenmeyen bir hatada
    # yalnızca mesajı loglamak hata ayıklamayı imkansızlaştırırdı.
    mock_logger.exception.assert_called_once()


def test_main_verbose_prints_packet_and_finding_details(tmp_path: Path, monkeypatch, capsys):
    capture = tmp_path / "ok.pcapng"
    capture.touch()
    monkeypatch.setattr("sys.argv", ["main.py", "-f", str(capture), "-v"])
    monkeypatch.setattr(config, "LOGS_DIR", tmp_path)

    with _PipelinePatches(packets=[_packet("10.0.0.1", "10.0.0.2")], findings=["BULGU-X"]):
        exit_code = main_module.main()

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "THREAT INTELLIGENCE" in out
    assert "İLK 3 PAKET" in out
    assert "THREAT FINDINGS" in out

    for handler in logging.getLogger().handlers[:]:
        handler.close()
        logging.getLogger().removeHandler(handler)


# ======================================================================
# Uçtan uca
# ======================================================================


DEMO_CAPTURE = Path(__file__).resolve().parent.parent / "samples" / "malicious" / "demo_capture.pcapng"


@pytest.mark.skipif(not DEMO_CAPTURE.exists(), reason="Demo capture bulunamadı")
def test_main_end_to_end_on_demo_capture(tmp_path: Path, monkeypatch):
    """Sentetik demo capture üzerinde gerçek boru hattı: mock yok.

    build_default_providers boşaltılıyor -- aksi halde geliştiricinin .env
    dosyasındaki anahtarlarla test sırasında gerçek ağ isteği yapılırdı.
    """
    monkeypatch.setattr("sys.argv", ["main.py", "-f", str(DEMO_CAPTURE)])
    monkeypatch.setattr(config, "LOGS_DIR", tmp_path)
    monkeypatch.setattr(config, "REPORTS_DIR", tmp_path / "reports")
    # ThreatIntelService boş liste kabul etmiyor; yapılandırılmamış tek bir
    # sahte provider veriyoruz -- sorgulanmaz, ağa çıkılmaz.
    unconfigured_provider = MagicMock()
    unconfigured_provider.name = "FakeProvider"
    unconfigured_provider.is_configured.return_value = False
    monkeypatch.setattr(main_module, "build_default_providers", lambda _session: [unconfigured_provider])

    exit_code = main_module.main()

    assert exit_code == 0

    report = tmp_path / "reports" / "malicious" / "demo_capture_report.html"
    assert report.exists(), "rapor beklenen yola yazılmalı"

    html = report.read_text(encoding="utf-8")
    # Demo capture 8 kuraldan 7'sini tetikliyor; rapor bunları içermeli.
    assert "SEC-PORT-SCAN-001" in html
    assert "SEC-DNS-TUNNEL-001" in html
    # Rapor tek dosya olmalı: dış kaynak referansı içermemeli.
    assert "src=\"http" not in html
    assert "href=\"http" not in html

    for handler in logging.getLogger().handlers[:]:
        handler.close()
        logging.getLogger().removeHandler(handler)


@pytest.mark.skipif(not DEMO_CAPTURE.exists(), reason="Demo capture bulunamadı")
def test_demo_capture_does_not_produce_port_scan_false_positive_from_dns():
    """Regresyon: demo capture'daki normal DNS/NTP yanıtları tarama sayılmamalı.

    Demo capture bilinçli olarak 53 -> farklı ephemeral portlar desenini
    içeriyor. Yanıt filtresi (_is_probable_response_packet) kaldırılırsa DNS
    sunucusu için ikinci bir port taraması bulgusu üretilir ve bu test kırılır.
    """
    from modules.parser import PCAPParser
    from modules.threat_detector import ThreatDetector

    packets = PCAPParser(DEMO_CAPTURE).parse()
    findings = ThreatDetector().detect(packets)

    scan_sources = {f.source for f in findings if f.rule_id == "SEC-PORT-SCAN-001"}
    assert scan_sources == {"10.0.0.66"}, "yalnızca gerçek tarayıcı host bulgu üretmeli"
