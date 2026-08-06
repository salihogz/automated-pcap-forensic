# tests/test_threat_detector.py
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
    assert len(findings) == 0


# --- Helper Function ---

def _make_scan_packet(epoch_time, src_ip, dst_ip, dst_port, transport="TCP", packet_id=0, tcp_flags="S"):
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
        tcp_flags=tcp_flags if transport == "TCP" else None,
    )


# --- Port Scan Detection Testleri ---

def test_port_scan_detects_many_ports_in_short_window():
    """Config'deki zaman penceresi içinde yeterli sayıda farklı porta erişim Port Scan olarak algılanmalıdır."""
    packets = [
        _make_scan_packet(1000.0 + i * 0.2, "10.0.0.5", "10.0.0.10", 1000 + i, tcp_flags="PA")
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
        _make_scan_packet(1000.0 + i * 0.2, "10.0.0.5", "10.0.0.10", 1000 + i, tcp_flags="PA")
        for i in range(20)
    )
    detector = ThreatDetector()
    findings = detector.detect(packet_generator)

    port_scan_findings = [f for f in findings if f.rule_id == "SEC-PORT-SCAN-001"]
    assert len(port_scan_findings) == 1


def test_port_scan_ignores_normal_traffic():
    """Aynı porta tekrar tekrar bağlanmak (normal davranış) bulgu üretmemeli."""
    packets = [
        _make_scan_packet(1000.0 + i, "10.0.0.5", "10.0.0.10", 443, tcp_flags="PA")
        for i in range(20)
    ]
    detector = ThreatDetector()
    findings = detector.detect(packets)

    assert not any(f.rule_id == "SEC-PORT-SCAN-001" for f in findings)


def test_port_scan_below_threshold_not_flagged():
    """Eşiğin altında farklı port -> bulgu üretilmemeli."""
    packets = [
        _make_scan_packet(1000.0 + i * 0.5, "10.0.0.5", "10.0.0.10", 2000 + i, tcp_flags="PA")
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
        _make_scan_packet(1000.0 + i * 100.0, "10.0.0.5", "10.0.0.10", 3000 + i, tcp_flags="PA")
        for i in range(20)
    ]
    detector = ThreatDetector()
    findings = detector.detect(packets)

    assert not any(f.rule_id == "SEC-PORT-SCAN-001" for f in findings)


def test_port_scan_multiple_attackers_produce_separate_findings():
    """İki farklı saldırgan aynı hedefi tararsa, her biri için ayrı bulgu üretilmeli."""
    attacker_1 = [
        _make_scan_packet(1000.0 + i * 0.1, "10.0.0.5", "10.0.0.10", 1000 + i, tcp_flags="PA")
        for i in range(16)
    ]
    attacker_2 = [
        _make_scan_packet(1000.0 + i * 0.1, "10.0.0.6", "10.0.0.10", 1000 + i, tcp_flags="PA")
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


def test_port_scan_ignores_dns_responses_from_local_resolver():
    """Yerel DNS sunucusunun istemciye verdiği cevaplar port taraması sayılmamalıdır.

    Gerçek bir capture'da gözlemlenen regresyon: bir DNS çözümleyicisi
    (10.106.4.20:53) istemcinin her sorgusuna farklı bir ephemeral porta
    (33615, 38777, 50922, ...) cevap verdiği için kural bunu "60 saniyede
    N farklı porta erişim" olarak okuyor, tamamen temiz bir capture için
    HIGH severity port taraması bulgusu üretip raporun genel risk
    seviyesini KRİTİK'e çıkarıyordu. Bu paketlerin ayırt edici özelliği
    yönüdür: SERVİS portundan (53) EPHEMERAL porta gitmeleri.
    """
    packets = [
        PacketInfo(
            id=i,
            epoch_time=1000.0 + i * 0.5,
            src_ip="10.106.4.20",
            dst_ip="10.30.80.23",
            is_ipv6=False,
            network_protocol="IPv4",
            transport_protocol="UDP",
            application_protocol="DNS",
            length=300,
            src_port=53,
            dst_port=33615 + i * 137,  # her cevap farklı bir ephemeral porta
            tcp_flags=None,
        )
        for i in range(40)
    ]
    detector = ThreatDetector()
    findings = detector.detect(packets)

    assert not any(f.rule_id == "SEC-PORT-SCAN-001" for f in findings)


def test_port_scan_still_detects_scan_towards_service_ports():
    """Yanıt filtresi, ephemeral kaynak porttan servis portlarına yapılan
    gerçek taramayı elemamalıdır (filtrenin fazla geniş olmadığının kanıtı)."""
    packets = [
        _make_scan_packet(
            1000.0 + i * 0.2, "10.0.0.5", "10.0.0.10", 20 + i, transport="UDP", packet_id=i
        )
        for i in range(20)
    ]
    detector = ThreatDetector()
    findings = detector.detect(packets)

    port_scan_findings = [f for f in findings if f.rule_id == "SEC-PORT-SCAN-001"]
    assert len(port_scan_findings) == 1
    assert port_scan_findings[0].source == "10.0.0.5"


def test_port_scan_multiple_bursts_same_pair_produce_multiple_findings():
    """
    Aynı (src_ip, dst_ip) çifti, aralarında zaman penceresinden (60s)
    daha uzun bir boşluk bırakarak İKİ AYRI scan patlaması yaparsa,
    her patlama için AYRI bir bulgu üretilmeli.
    """
    burst_1 = [
        _make_scan_packet(1000.0 + i * 0.2, "10.0.0.5", "10.0.0.10", 1000 + i, tcp_flags="PA")
        for i in range(16)
    ]
    # 200 saniyelik boşluk (time_window=60'tan büyük) -> ayrı bir olay
    burst_2 = [
        _make_scan_packet(1300.0 + i * 0.2, "10.0.0.5", "10.0.0.10", 2000 + i, tcp_flags="PA")
        for i in range(16)
    ]
    detector = ThreatDetector()
    findings = detector.detect(burst_1 + burst_2)

    port_scan_findings = [f for f in findings if f.rule_id == "SEC-PORT-SCAN-001"]
    assert len(port_scan_findings) == 2
    timestamps = sorted(f.timestamp for f in port_scan_findings)
    assert timestamps[1] - timestamps[0] > config.PORT_SCAN_TIME_WINDOW_SECONDS


# --- Diğer Tehdit Kuralları Testleri ---

def test_syn_scan_detection():
    """SYN taramasının tespit edildiğini doğrular."""
    packets = [
        _make_scan_packet(1000.0 + i * 0.2, "10.0.0.5", "10.0.0.10", 1000 + i, tcp_flags="S")
        for i in range(12)
    ]
    detector = ThreatDetector()
    findings = detector.detect(packets)

    syn_scan_findings = [f for f in findings if f.rule_id == "SEC-SYN-SCAN-001"]
    assert len(syn_scan_findings) == 1
    assert syn_scan_findings[0].source == "10.0.0.5"


def test_icmp_flood_detection():
    """ICMP Flood tespiti test eder."""
    packets = [
        PacketInfo(
            id=i,
            epoch_time=1000.0 + i * 0.05,
            src_ip="10.0.0.5",
            dst_ip="10.0.0.10",
            is_ipv6=False,
            network_protocol="IPv4",
            transport_protocol="ICMP",
            application_protocol=None,
            length=64,
            src_port=None,
            dst_port=None,
            tcp_flags=None,
        )
        for i in range(105)
    ]
    detector = ThreatDetector()
    findings = detector.detect(packets)

    icmp_findings = [f for f in findings if f.rule_id == "SEC-ICMP-FLOOD-001"]
    assert len(icmp_findings) == 1
    assert icmp_findings[0].evidence["packet_count"] >= 100


def test_dns_tunneling_detection():
    """DNS tünelleme tespitini doğrular."""
    packets = [
        PacketInfo(
            id=i,
            epoch_time=1000.0 + i * 0.1,
            src_ip="192.168.1.50",
            dst_ip="8.8.8.8",
            is_ipv6=False,
            network_protocol="IPv4",
            transport_protocol="UDP",
            application_protocol="DNS",
            length=120,
            src_port=53530,
            dst_port=53,
            tcp_flags=None,
            dns_query_name=f"sub{i}.tunneldomain.com",
            dns_query_type="TXT",
        )
        for i in range(35)
    ]
    detector = ThreatDetector()
    findings = detector.detect(packets)

    dns_findings = [f for f in findings if f.rule_id == "SEC-DNS-TUNNEL-001"]
    assert len(dns_findings) == 1
    assert dns_findings[0].evidence["base_domain"] == "tunneldomain.com"


def test_dns_tunneling_base_domain_handles_multi_label_public_suffix():
    """base_domain çıkarımı, ikinci seviye TLD'lerde (örn. .com.tr) sondan
    iki etiketi ("com.tr") değil, gerçek kayıtlı alan adını ("evilcorp.com.tr")
    döndürmelidir; aksi halde bu alan adı yanlışlıkla suffix'in kendisiyle
    eşleşir (bkz. ThreatDetector._compute_base_domain)."""
    packets = [
        PacketInfo(
            id=i,
            epoch_time=1000.0 + i * 0.1,
            src_ip="192.168.1.50",
            dst_ip="8.8.8.8",
            is_ipv6=False,
            network_protocol="IPv4",
            transport_protocol="UDP",
            application_protocol="DNS",
            length=120,
            src_port=53530,
            dst_port=53,
            tcp_flags=None,
            dns_query_name=f"sub{i}.evilcorp.com.tr",
            dns_query_type="TXT",
        )
        for i in range(35)
    ]
    detector = ThreatDetector()
    findings = detector.detect(packets)

    dns_findings = [f for f in findings if f.rule_id == "SEC-DNS-TUNNEL-001"]
    assert len(dns_findings) == 1
    assert dns_findings[0].evidence["base_domain"] == "evilcorp.com.tr"


def test_dns_tunneling_does_not_merge_unrelated_domains_under_same_suffix():
    """İki ilgisiz ".com.tr" alan adına yapılan, her biri eşiğin altında kalan
    sorgular, eski (sondan-iki-etiket) mantıkta olduğu gibi tek bir "com.tr"
    kovasında birleşip yanlış-pozitif bir tünelleme bulgusu üretmemelidir."""
    site1_packets = [
        PacketInfo(
            id=i,
            epoch_time=1000.0 + i * 0.1,
            src_ip="192.168.1.50",
            dst_ip="8.8.8.8",
            is_ipv6=False,
            network_protocol="IPv4",
            transport_protocol="UDP",
            application_protocol="DNS",
            length=120,
            src_port=53530,
            dst_port=53,
            tcp_flags=None,
            dns_query_name="site1.com.tr",
            dns_query_type="A",
        )
        for i in range(15)
    ]
    site2_packets = [
        PacketInfo(
            id=100 + i,
            epoch_time=1000.0 + i * 0.1,
            src_ip="192.168.1.50",
            dst_ip="8.8.8.8",
            is_ipv6=False,
            network_protocol="IPv4",
            transport_protocol="UDP",
            application_protocol="DNS",
            length=120,
            src_port=53531,
            dst_port=53,
            tcp_flags=None,
            dns_query_name="unrelated2.com.tr",
            dns_query_type="A",
        )
        for i in range(20)
    ]
    detector = ThreatDetector()
    findings = detector.detect(site1_packets + site2_packets)

    dns_findings = [f for f in findings if f.rule_id == "SEC-DNS-TUNNEL-001"]
    assert len(dns_findings) == 0


def test_long_domain_detection():
    """Anormal uzunluktaki domain tespiti."""
    long_domain = "a" * 60 + ".com"
    packet = PacketInfo(
        id=1,
        epoch_time=1000.0,
        src_ip="192.168.1.50",
        dst_ip="8.8.8.8",
        is_ipv6=False,
        network_protocol="IPv4",
        transport_protocol="UDP",
        application_protocol="DNS",
        length=120,
        src_port=53530,
        dst_port=53,
        tcp_flags=None,
        dns_query_name=long_domain,
        dns_query_type="A",
    )
    detector = ThreatDetector()
    findings = detector.detect([packet])

    long_findings = [f for f in findings if f.rule_id == "SEC-LONG-DOMAIN-001"]
    assert len(long_findings) == 1


def test_dga_domain_detection():
    """DGA domain tespiti test eder."""
    dga_domain = "kqxvzptbnjwlmfr.com"  # etiket entropisi ~3.9, DGA_ENTROPY_THRESHOLD (3.5) üzerinde
    packet = PacketInfo(
        id=1,
        epoch_time=1000.0,
        src_ip="192.168.1.50",
        dst_ip="8.8.8.8",
        is_ipv6=False,
        network_protocol="IPv4",
        transport_protocol="UDP",
        application_protocol="DNS",
        length=120,
        src_port=53530,
        dst_port=53,
        tcp_flags=None,
        dns_query_name=dga_domain,
        dns_query_type="A",
    )
    detector = ThreatDetector()
    findings = detector.detect([packet])

    dga_findings = [f for f in findings if f.rule_id == "SEC-DGA-001"]
    assert len(dga_findings) == 1


def test_exfiltration_detection():
    """Exfiltration (Veri sızdırma) tespiti test eder."""
    packets = [
        PacketInfo(
            id=i,
            epoch_time=1000.0 + i,
            src_ip="192.168.1.50",
            dst_ip="93.184.216.34",  # Public IP
            is_ipv6=False,
            network_protocol="IPv4",
            transport_protocol="TCP",
            application_protocol=None,
            length=10 * 1024 * 1024,  # 10 MB
            src_port=54321,
            dst_port=443,
            tcp_flags="PA",
        )
        for i in range(6)
    ]
    detector = ThreatDetector()
    findings = detector.detect(packets)

    exfil_findings = [f for f in findings if f.rule_id == "SEC-EXFIL-001"]
    assert len(exfil_findings) == 1
    assert exfil_findings[0].evidence["total_megabytes"] >= 50.0
    assert exfil_findings[0].evidence["time_window_seconds"] == config.EXFILTRATION_TIME_WINDOW_SECONDS


def test_exfiltration_ignores_slow_benign_transfer_over_long_capture():
    """Zaman penceresi olmadan (eski davranış) toplam hacim eşiği aşan, ama
    aslında saatlerce yayılmış düşük hızlı sıradan bir aktarım (örn. büyük bir
    dosya indirmesi), pencereli kontrolde HİÇBİR tekil pencerede eşiği
    aşmadığı için artık bulgu üretmemelidir."""
    # 100 paket * 1 MB, 72 saniye arayla (toplam ~2 saat, 100 MB) ->
    # herhangi bir 300 saniyelik pencereye en fazla ~4-5 paket (~4-5 MB) düşer,
    # bu da EXFILTRATION_THRESHOLD'un (50 MB) çok altındadır.
    packets = [
        PacketInfo(
            id=i,
            epoch_time=1000.0 + i * 72,
            src_ip="192.168.1.50",
            dst_ip="93.184.216.34",  # Public IP
            is_ipv6=False,
            network_protocol="IPv4",
            transport_protocol="TCP",
            application_protocol=None,
            length=1 * 1024 * 1024,  # 1 MB
            src_port=54321,
            dst_port=443,
            tcp_flags="PA",
        )
        for i in range(100)
    ]
    detector = ThreatDetector()
    findings = detector.detect(packets)

    exfil_findings = [f for f in findings if f.rule_id == "SEC-EXFIL-001"]
    assert len(exfil_findings) == 0


@pytest.mark.parametrize(
    "multicast_dst",
    [
        "239.255.255.250",  # SSDP / UPnP
        "224.0.0.251",      # mDNS
        "224.0.0.252",      # LLMNR
    ],
)
def test_exfiltration_ignores_multicast_destinations(multicast_dst):
    """Regresyon: multicast hedefler "dış IP" sayılmamalı.

    `ipaddress.is_global` multicast adresleri için True döner. Bu tek başına
    kullanıldığında, yerel ağdaki yüksek hacimli yayın trafiği (SSDP duyuruları,
    çok yayınlı video) SEC-EXFIL-001 tarafından CRITICAL "veri sızdırma" olarak
    raporlanıyordu — oysa bu trafik ağdan hiç çıkmaz.
    """
    packets = [
        PacketInfo(
            id=i,
            epoch_time=1000.0 + i,
            src_ip="192.168.1.50",
            dst_ip=multicast_dst,
            is_ipv6=False,
            network_protocol="IPv4",
            transport_protocol="UDP",
            application_protocol=None,
            length=10 * 1024 * 1024,  # 10 MB -> toplam 60 MB, eşiğin (50 MB) üstünde
            src_port=54321,
            dst_port=1900,
            tcp_flags=None,
        )
        for i in range(6)
    ]
    findings = ThreatDetector().detect(packets)

    assert [f for f in findings if f.rule_id == "SEC-EXFIL-001"] == []


def test_is_egress_traffic_multicast_and_public():
    """_is_egress_traffic: gerçek public hedef kabul, multicast ret."""
    assert ThreatDetector._is_egress_traffic("192.168.1.50", "93.184.216.34") is True
    assert ThreatDetector._is_egress_traffic("192.168.1.50", "239.255.255.250") is False
    assert ThreatDetector._is_egress_traffic("192.168.1.50", "ff02::fb") is False
    # Hedef zaten iç ağdaysa egress değildir.
    assert ThreatDetector._is_egress_traffic("192.168.1.50", "192.168.1.60") is False
    # Ayrıştırılamayan adres sessizce False döner (kural çökmemeli).
    assert ThreatDetector._is_egress_traffic("gecersiz", "93.184.216.34") is False


def test_long_domain_and_dga_share_query_domain_map():
    """detect() alan adı haritasını bir kez kurup iki kurala da vermeli.

    Harita paylaşımı bir optimizasyon; ancak kuralların TEK BAŞINA da
    çalışabilmesi (harita verilmezse kendisi kurar) korunmalıdır, aksi halde
    kural tek başına test edilemez hale gelir.
    """
    packet = PacketInfo(
        id=1,
        epoch_time=1700000000.0,
        src_ip="10.0.0.5",
        dst_ip="10.0.0.1",
        is_ipv6=False,
        network_protocol="IPv4",
        transport_protocol="UDP",
        application_protocol="DNS",
        length=90,
        src_port=53000,
        dst_port=53,
        tcp_flags=None,
        dns_query_name="a" * 60 + ".example.com",
        dns_query_type="TXT",
    )
    detector = ThreatDetector()

    standalone = detector._detect_long_domains([packet])
    shared = detector._detect_long_domains(
        [packet], detector._collect_unique_query_domains([packet])
    )

    assert len(standalone) == 1
    assert [f.rule_id for f in standalone] == [f.rule_id for f in shared]
    assert standalone[0].evidence == shared[0].evidence


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
