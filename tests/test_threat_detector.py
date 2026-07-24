"""
test_threat_detector.py - Threat Detector Framework Unit Testleri
"""
from dataclasses import FrozenInstanceError

import pytest

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
        tcp_flags=None,   # UDP paketinde TCP flag'i olmaz - PacketInfo tüm alanları zorunlu kılıyor
    )
    detector = ThreatDetector()
    findings = detector.detect([dummy_packet])

    assert isinstance(findings, list)
    assert len(findings) == 0  # Henüz kural eklenmediği için 0 olmalı