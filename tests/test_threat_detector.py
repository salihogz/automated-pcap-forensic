"""
test_threat_detector.py - Threat Detector Framework Unit Testleri
"""
from dataclasses import FrozenInstanceError

import pytest

import config
from modules.models import PacketInfo, ThreatFinding, ThreatSeverity
from modules.threat_detector import ThreatDetector


def test_threat_finding_instantiation():
    """ThreatFinding dataclass'ının doğru oluşturulduğunu doğrular."""
    finding = ThreatFinding(
        rule_id="TEST-001",
        title="Test Tehdidi",
        severity=ThreatSeverity.HIGH,
        description="Bu bir test açıklamasıdır.",
        evidence={"count": 5},
        source="192.168.1.100",
        destination="10.0.0.1",
        timestamp=1700000000.0,
    )
    assert finding.rule_id == "TEST-001"
    assert finding.severity == ThreatSeverity.HIGH
    assert finding.severity.value == "HIGH"
    assert finding.source == "192.168.1.100"
    assert finding.evidence["count"] == 5


def test_threat_finding_is_immutable():
    """ThreatFinding oluşturulduktan sonra değiştirilemez (frozen)."""
    finding = ThreatFinding(
        rule_id="TEST-002",
        title="Immutable Kontrolü",
        severity=ThreatSeverity.LOW,
        description="x",
        evidence={},
        source="1.1.1.1",
    )
    with pytest.raises(FrozenInstanceError):
        finding.severity = ThreatSeverity.CRITICAL


def test_threat_detector_empty_packets():
    """Boş paket listesi verildiğinde boş bulgu listesi döndüğünü doğrular."""
    detector = ThreatDetector()
    findings = detector.detect([])

    assert isinstance(findings, list)
    assert len(findings) == 0


def test_threat_detector_with_dummy_packets():
    """Paketler gönderildiğinde framework'ün çökmeden çalıştığını doğrular."""
    dummy_packet = PacketInfo(
        id=1,
        epoch_time=1700000000.0,
        src_ip="192.168.1.5",
        dst_ip="8.8.8.8",
        is_ipv6=False,
        network_protocol="IPv4",
        transport_protocol="UDP",
        application_protocol="DNS",
        length=64,
        src_port=5353,
        dst_port=53,
        tcp_flags=None,
    )
    detector = ThreatDetector()
    findings = detector.detect([dummy_packet])

    assert isinstance(findings, list)
    assert len(findings) == 0  # Henüz kural eklenmediği için 0 olmalı


# --- Helper Function ---

def _make_scan_packet(epoch_time, src_ip, dst_ip, dst_port, transport="TCP", packet_id=0):
    return PacketInfo(
        id=packet_id,
        epoch_time=epoch_time,
        src_ip=src_ip,
        dst_ip=dst_ip,
        is_ipv6=False,
        network_protocol="IPv4",
        transport_protocol=transport,
        application_protocol=None,
        length=60,
        src_port=54321,
        dst_port=dst_port,
        tcp_flags="S" if transport == "TCP" else None,
    )


# --- Port Scan Detection Testleri ---

def test_port_scan_detects_many_ports_in_short_window():
    """Config'deki zaman penceresi içinde yeterli sayıda farklı porta erişim Port Scan olarak algılanmalıdır."""
    packets = [
        _make_scan_packet(1000.0 + i * 0.2, "10.0.0.5", "10.0.0.10", 1000 + i)
        for i in range(20)
    ]
    detector = ThreatDetector()
    findings = detector.detect(packets)

    port_scan_findings = [f for f in findings if f.rule_id == "SEC-PORT-SCAN-001"]
    assert len(port_scan_findings) == 1
    assert port_scan_findings[0].source == "10.0.0.5"
    assert port_scan_findings[0].destination == "10.0.0.10"
    assert port_scan_findings[0].evidence["distinct_port_count"] >= 15


def test_port_scan_detects_udp_scan():
    """UDP protokolü üzerinden yapılan port taramalarının tespit edildiğini doğrular."""
    packets = [
        _make_scan_packet(1000.0 + i * 0.2, "10.0.0.5", "10.0.0.10", 1000 + i, transport="UDP")
        for i in range(20)
    ]
    detector = ThreatDetector()
    findings = detector.detect(packets)

    port_scan_findings = [f for f in findings if f.rule_id == "SEC-PORT-SCAN-001"]
    assert len(port_scan_findings) == 1
    assert port_scan_findings[0].source == "10.0.0.5"


def test_port_scan_works_with_generator_input():
    """detect() metoduna generator (Iterable) iletildiğinde doğru çalıştığını doğrular."""
    packet_generator = (
        _make_scan_packet(1000.0 + i * 0.2, "10.0.0.5", "10.0.0.10", 1000 + i)
        for i in range(20)
    )
    detector = ThreatDetector()
    findings = detector.detect(packet_generator)

    port_scan_findings = [f for f in findings if f.rule_id == "SEC-PORT-SCAN-001"]
    assert len(port_scan_findings) == 1


def test_port_scan_ignores_normal_traffic():
    """Aynı porta tekrar tekrar bağlanmak (normal davranış) bulgu üretmemeli."""
    packets = [
        _make_scan_packet(1000.0 + i, "10.0.0.5", "10.0.0.10", 443)
        for i in range(20)
    ]
    detector = ThreatDetector()
    findings = detector.detect(packets)

    assert not any(f.rule_id == "SEC-PORT-SCAN-001" for f in findings)


def test_port_scan_below_threshold_not_flagged():
    """Eşiğin altında farklı port -> bulgu üretilmemeli."""
    packets = [
        _make_scan_packet(1000.0 + i * 0.5, "10.0.0.5", "10.0.0.10", 2000 + i)
        for i in range(10)
    ]
    detector = ThreatDetector()
    findings = detector.detect(packets)

    assert not any(f.rule_id == "SEC-PORT-SCAN-001" for f in findings)


def test_port_scan_ports_spread_outside_window_not_flagged():
    """
    Toplamda 20 farklı port var (ön elemeyi geçer) ama her biri 100 saniye
    arayla geldiği için HİÇBİR 60 saniyelik pencerede eşiğe ulaşılmaz.
    """
    packets = [
        _make_scan_packet(1000.0 + i * 100.0, "10.0.0.5", "10.0.0.10", 3000 + i)
        for i in range(20)
    ]
    detector = ThreatDetector()
    findings = detector.detect(packets)

    assert not any(f.rule_id == "SEC-PORT-SCAN-001" for f in findings)


def test_port_scan_multiple_attackers_produce_separate_findings():
    """İki farklı saldırgan aynı hedefi tararsa, her biri için ayrı bulgu üretilmeli."""
    attacker_1 = [
        _make_scan_packet(1000.0 + i * 0.1, "10.0.0.5", "10.0.0.10", 1000 + i)
        for i in range(16)
    ]
    attacker_2 = [
        _make_scan_packet(1000.0 + i * 0.1, "10.0.0.6", "10.0.0.10", 1000 + i)
        for i in range(16)
    ]
    detector = ThreatDetector()
    findings = detector.detect(attacker_1 + attacker_2)

    port_scan_findings = [f for f in findings if f.rule_id == "SEC-PORT-SCAN-001"]
    sources = {f.source for f in port_scan_findings}
    assert len(port_scan_findings) == 2
    assert sources == {"10.0.0.5", "10.0.0.6"}


def test_port_scan_ignores_icmp_packets():
    """ICMP paketlerinin portu yoktur; port scan sayımına dahil edilmemeli."""
    packets = [
        PacketInfo(
            id=i,
            epoch_time=1000.0 + i * 0.1,
            src_ip="10.0.0.5",
            dst_ip="10.0.0.10",
            is_ipv6=False,
            network_protocol="IPv4",
            transport_protocol="ICMP",
            application_protocol=None,
            length=60,
            src_port=None,
            dst_port=None,
            tcp_flags=None,
        )
        for i in range(20)
    ]
    detector = ThreatDetector()
    findings = detector.detect(packets)

    assert not any(f.rule_id == "SEC-PORT-SCAN-001" for f in findings)


def test_port_scan_multiple_bursts_same_pair_produce_multiple_findings():
    """
    Aynı (src_ip, dst_ip) çifti, aralarında zaman penceresinden (60s)
    daha uzun bir boşluk bırakarak İKİ AYRI scan patlaması yaparsa,
    her patlama için AYRI bir bulgu üretilmeli.
    """
    burst_1 = [
        _make_scan_packet(1000.0 + i * 0.2, "10.0.0.5", "10.0.0.10", 1000 + i)
        for i in range(16)
    ]
    # 200 saniyelik boşluk (time_window=60'tan büyük) -> ayrı bir olay
    burst_2 = [
        _make_scan_packet(1300.0 + i * 0.2, "10.0.0.5", "10.0.0.10", 2000 + i)
        for i in range(16)
    ]
    detector = ThreatDetector()
    findings = detector.detect(burst_1 + burst_2)

    port_scan_findings = [f for f in findings if f.rule_id == "SEC-PORT-SCAN-001"]
    assert len(port_scan_findings) == 2
    timestamps = sorted(f.timestamp for f in port_scan_findings)
    assert timestamps[1] - timestamps[0] > config.PORT_SCAN_TIME_WINDOW_SECONDS


# --- _is_valid_transport_packet Parametrik Testleri ---

@pytest.mark.parametrize(
    "invalid_packet",
    [
        # src_ip eksik
        _make_scan_packet(1000.0, None, "10.0.0.10", 80),
        # dst_ip eksik
        _make_scan_packet(1000.0, "10.0.0.5", None, 80),
        # dst_port None
        _make_scan_packet(1000.0, "10.0.0.5", "10.0.0.10", None),
        # dst_port <= 0 (geçersiz port)
        _make_scan_packet(1000.0, "10.0.0.5", "10.0.0.10", 0),
        _make_scan_packet(1000.0, "10.0.0.5", "10.0.0.10", -80),
        # epoch_time eksik veya <= 0
        _make_scan_packet(None, "10.0.0.5", "10.0.0.10", 80),
        _make_scan_packet(0.0, "10.0.0.5", "10.0.0.10", 80),
        _make_scan_packet(-100.0, "10.0.0.5", "10.0.0.10", 80),
        # Desteklenmeyen transport protokolü
        _make_scan_packet(1000.0, "10.0.0.5", "10.0.0.10", 80, transport="ICMP"),
        _make_scan_packet(1000.0, "10.0.0.5", "10.0.0.10", 80, transport="ARP"),
        _make_scan_packet(1000.0, "10.0.0.5", "10.0.0.10", 80, transport=None),
    ],
)
def test_is_valid_transport_packet_rejects_invalid_packets(invalid_packet):
    """
    Bozuk veya taşıma katmanı tespiti için yetersiz olan paketlerin
    _is_valid_transport_packet tarafından reddedildiğini (False döndüğünü) doğrular.
    """
    assert ThreatDetector._is_valid_transport_packet(invalid_packet) is False


@pytest.mark.parametrize(
    "valid_packet",
    [
        _make_scan_packet(1000.0, "10.0.0.5", "10.0.0.10", 80, transport="TCP"),
        _make_scan_packet(1000.0, "10.0.0.5", "10.0.0.10", 53, transport="UDP"),
    ],
)
def test_is_valid_transport_packet_accepts_valid_packets(valid_packet):
    """Doğru yapılandırılmış TCP/UDP paketlerinin kabul edildiğini (True döndüğünü) doğrular."""
    assert ThreatDetector._is_valid_transport_packet(valid_packet) is True