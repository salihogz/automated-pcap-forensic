"""
tests/test_parser.py - PCAPParser Unit ve Entegrasyon Testleri

İki katman test içerir:
1. Internal metod testleri: scapy ile bellekte paket üretip
   _extract_network_layer / _extract_application_protocol /
   _extract_tcp_flags / _parse_single_packet'i doğrudan çağırır.
   Gerçek bir .pcap dosyasına ihtiyaç duymaz, hızlıdır.
2. parse() entegrasyon testleri: tmp_path fixture'ı ile geçici bir
   .pcap dosyası yazıp PCAPParser.parse() uçtan uca çalıştırılır
   (validate_file + PcapReader streaming + hata toleransı dahil).
"""
import logging
from unittest.mock import patch

import pytest
from scapy.all import ARP, DHCP, DNS, ICMP, IP, NTP, SNMP, TCP, UDP, Ether, IPv6
from scapy.utils import wrpcap

import config
from modules.parser import PCAPParser

# ---------------------------------------------------------------------------
# Packet Construction Helpers
# ---------------------------------------------------------------------------

def make_tcp_packet(src="10.0.0.1", dst="10.0.0.2", sport=12345, dport=80, flags="S"):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)


def make_udp_packet(src="10.0.0.1", dst="10.0.0.2", sport=54321, dport=53, payload=None):
    pkt = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    return pkt / payload if payload else pkt


def make_icmp_packet(src="10.0.0.1", dst="10.0.0.2"):
    return Ether() / IP(src=src, dst=dst) / ICMP()


def make_ipv6_packet(src="::1", dst="::2", sport=12345, dport=443):
    return Ether() / IPv6(src=src, dst=dst) / TCP(sport=sport, dport=dport)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def dummy_parser():
    """Dosya erişimi gerektirmeyen internal metod testleri için parser."""
    return PCAPParser("dummy.pcap")


# ---------------------------------------------------------------------------
# validate_file() testleri
# ---------------------------------------------------------------------------

def test_validate_file_raises_for_missing_file(tmp_path):
    missing = tmp_path / "does_not_exist.pcap"
    parser = PCAPParser(missing)

    with pytest.raises(FileNotFoundError):
        parser.validate_file()


def test_validate_file_raises_for_directory(tmp_path):
    parser = PCAPParser(tmp_path)

    with pytest.raises(ValueError):
        parser.validate_file()


def test_validate_file_raises_for_unsupported_extension(tmp_path):
    bad_file = tmp_path / "notes.txt"
    bad_file.write_text("bu bir pcap degil", encoding="utf-8")
    parser = PCAPParser(bad_file)

    with pytest.raises(ValueError):
        parser.validate_file()


def test_validate_file_accepts_supported_extension(tmp_path):
    pcap_file = tmp_path / "sample.pcap"
    wrpcap(str(pcap_file), [make_tcp_packet()])
    parser = PCAPParser(pcap_file)

    parser.validate_file()


# ---------------------------------------------------------------------------
# _extract_network_layer() testleri
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "packet, expected_src, expected_dst, expected_proto, expected_is_ipv6",
    [
        (make_tcp_packet(src="10.0.0.1", dst="10.0.0.2"), "10.0.0.1", "10.0.0.2", "IPv4", False),
        (make_ipv6_packet(src="::1", dst="::2"), "::1", "::2", "IPv6", True),
        (Ether() / ARP(psrc="10.0.0.5", pdst="10.0.0.6"), "10.0.0.5", "10.0.0.6", "ARP", False),
        (Ether(), None, None, config.UNKNOWN_PROTOCOL, False),
    ],
    ids=["ipv4", "ipv6", "arp", "unknown"],
)
def test_extract_network_layer(packet, expected_src, expected_dst, expected_proto, expected_is_ipv6):
    src, dst, proto, is_ipv6 = PCAPParser._extract_network_layer(packet)

    assert src == expected_src
    assert dst == expected_dst
    assert proto == expected_proto
    assert is_ipv6 is expected_is_ipv6


# ---------------------------------------------------------------------------
# _extract_application_protocol() testleri
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "packet, src_port, dst_port, transport_protocol, expected",
    [
        (make_udp_packet(sport=53, dport=51000, payload=DNS()), 53, 51000, "UDP", "DNS"),
        (make_tcp_packet(sport=54321, dport=8080), 54321, 8080, "TCP", "HTTP"),
        (make_tcp_packet(sport=54321, dport=443), 54321, 443, "TCP", "TLS"),
        (make_tcp_packet(sport=54321, dport=22), 54321, 22, "TCP", "SSH"),
        (make_udp_packet(sport=68, dport=67, payload=DHCP()), 68, 67, "UDP", "DHCP"),
        (make_udp_packet(sport=54321, dport=123, payload=NTP()), 54321, 123, "UDP", "NTP"),
        (make_udp_packet(sport=54321, dport=161, payload=SNMP()), 54321, 161, "UDP", "SNMP"),
        (make_tcp_packet(sport=54321, dport=59999), 54321, 59999, "TCP", None),
        # QUIC/HTTP3: port 443 fakat taşıma UDP'dir -> TLS DEĞİL, QUIC olarak
        # sınıflandırılmalı (TLS yalnızca TCP üzerinde koşar). Bu senaryo
        # gerçek capture'larda (Cloudflare/Google CDN) baskın hacimde
        # görülebilir; transport kontrolü olmadan hepsi yanlışlıkla "TLS"
        # sayılıp protokol dağılımı istatistiklerini bozardı.
        (make_udp_packet(sport=54321, dport=443), 54321, 443, "UDP", "QUIC"),
        # Port 80 üzerinden UDP: standart bir protokol değildir, HTTP TCP
        # gerektirdiğinden bu paket tanınmamalı (None) döner.
        (make_udp_packet(sport=54321, dport=80), 54321, 80, "UDP", None),
    ],
    ids=["dns", "http", "tls", "ssh", "dhcp", "ntp", "snmp", "unknown", "quic-udp-443", "udp-80-unclassified"],
)
def test_extract_application_protocol(packet, src_port, dst_port, transport_protocol, expected):
    result = PCAPParser._extract_application_protocol(packet, src_port, dst_port, transport_protocol)

    assert result == expected


# ---------------------------------------------------------------------------
# _extract_tcp_flags() testleri
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "flags_input, expected_flags",
    [
        ("S", "S"),
        ("SA", "SA"),
        ("FA", "FA"),
        ("PA", "PA"),
    ],
    ids=["syn", "syn_ack", "fin_ack", "psh_ack"],
)
def test_extract_tcp_flags_returns_flag_string(flags_input, expected_flags):
    tcp_layer = TCP(flags=flags_input)

    result = PCAPParser._extract_tcp_flags(tcp_layer)

    assert result == expected_flags


def test_extract_tcp_flags_returns_default_when_no_flags_set():
    tcp_layer = TCP(flags=0)

    result = PCAPParser._extract_tcp_flags(tcp_layer)

    assert result == config.DEFAULT_FLAGS


# ---------------------------------------------------------------------------
# _parse_single_packet() testleri
# ---------------------------------------------------------------------------

def test_parse_single_packet_tcp_fields(dummy_parser):
    packet = make_tcp_packet(src="10.0.0.1", dst="10.0.0.2", sport=12345, dport=80, flags="S")

    info = dummy_parser._parse_single_packet(packet, index=1)

    assert info.id == 1
    assert info.src_ip == "10.0.0.1"
    assert info.dst_ip == "10.0.0.2"
    assert info.network_protocol == "IPv4"
    assert info.transport_protocol == "TCP"
    assert info.application_protocol == "HTTP"
    assert info.src_port == 12345
    assert info.dst_port == 80
    assert info.tcp_flags == "S"
    assert info.length == len(packet)


def test_parse_single_packet_udp_dns(dummy_parser):
    packet = make_udp_packet(src="8.8.8.8", dst="10.0.0.5", sport=53, dport=51000, payload=DNS())

    info = dummy_parser._parse_single_packet(packet, index=2)

    assert info.transport_protocol == "UDP"
    assert info.application_protocol == "DNS"
    assert info.tcp_flags is None
    assert info.length == len(packet)


def test_parse_single_packet_icmp_has_no_ports(dummy_parser):
    packet = make_icmp_packet(src="10.0.0.1", dst="10.0.0.2")

    info = dummy_parser._parse_single_packet(packet, index=3)

    assert info.transport_protocol == "ICMP"
    assert info.src_port is None
    assert info.dst_port is None
    assert info.tcp_flags is None
    assert info.application_protocol is None


def test_parse_single_packet_invalid_timestamp_defaults_to_zero(dummy_parser):
    packet = make_tcp_packet()
    packet.time = "invalid_timestamp"  # Geçersiz/dönüştürülemeyen zaman damgası simülasyonu

    info = dummy_parser._parse_single_packet(packet, index=4)

    assert info.epoch_time == 0.0


# ---------------------------------------------------------------------------
# parse() entegrasyon testleri
# ---------------------------------------------------------------------------

def test_parse_reads_multiple_packets_from_real_pcap(tmp_path):
    packets = [
        make_tcp_packet(src="10.0.0.1", dst="10.0.0.2", sport=1111, dport=80),
        make_udp_packet(src="10.0.0.3", dst="10.0.0.4", sport=53, dport=51000, payload=DNS()),
        make_icmp_packet(src="10.0.0.5", dst="10.0.0.6"),
    ]
    pcap_file = tmp_path / "traffic.pcap"
    wrpcap(str(pcap_file), packets)

    parser = PCAPParser(pcap_file)
    result = parser.parse()

    assert len(result) == 3
    assert [p.id for p in result] == [1, 2, 3]

    # Protokol ve uygulama eşleşmeleri
    assert result[0].transport_protocol == "TCP"
    assert result[1].application_protocol == "DNS"
    assert result[2].transport_protocol == "ICMP"

    # Sıralama ve IP eşleşme doğrulamaları
    assert result[0].src_ip == "10.0.0.1"
    assert result[0].dst_ip == "10.0.0.2"
    assert result[1].src_ip == "10.0.0.3"
    assert result[1].dst_ip == "10.0.0.4"
    assert result[2].src_ip == "10.0.0.5"
    assert result[2].dst_ip == "10.0.0.6"


def test_parse_reads_ipv6_traffic_from_real_pcap(tmp_path):
    packets = [
        make_ipv6_packet(src="2001:db8::1", dst="2001:db8::2", dport=443),
    ]
    pcap_file = tmp_path / "ipv6_traffic.pcap"
    wrpcap(str(pcap_file), packets)

    parser = PCAPParser(pcap_file)
    result = parser.parse()

    assert len(result) == 1
    assert result[0].is_ipv6 is True
    assert result[0].network_protocol == "IPv6"
    assert result[0].src_ip == "2001:db8::1"
    assert result[0].dst_ip == "2001:db8::2"


def test_parse_handles_ethernet_only_unknown_protocol(tmp_path):
    packets = [Ether()]
    pcap_file = tmp_path / "unknown_proto.pcap"
    wrpcap(str(pcap_file), packets)

    parser = PCAPParser(pcap_file)
    result = parser.parse()

    assert len(result) == 1
    assert result[0].network_protocol == config.UNKNOWN_PROTOCOL


def test_parse_raises_for_missing_file():
    parser = PCAPParser("/kesinlikle/olmayan/bir/dosya.pcap")

    with pytest.raises(FileNotFoundError):
        parser.parse()


def test_parse_raises_for_unsupported_extension(tmp_path):
    bad_file = tmp_path / "data.txt"
    bad_file.write_text("pcap degil", encoding="utf-8")
    parser = PCAPParser(bad_file)

    with pytest.raises(ValueError):
        parser.parse()


def test_parse_continues_after_single_packet_failure(tmp_path):
    packets = [
        make_tcp_packet(src="10.0.0.1", dst="10.0.0.2", sport=1111, dport=80),
        make_tcp_packet(src="10.0.0.3", dst="10.0.0.4", sport=2222, dport=80),
        make_tcp_packet(src="10.0.0.5", dst="10.0.0.6", sport=3333, dport=80),
    ]
    pcap_file = tmp_path / "traffic.pcap"
    wrpcap(str(pcap_file), packets)

    parser = PCAPParser(pcap_file)

    # Orijinal metot referansı patch öncesinde saklanıyor
    original_parse = PCAPParser._parse_single_packet
    call_count = 0

    def flaky_parse(self, packet, index):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ValueError("simüle edilmiş bozuk paket")
        return original_parse(self, packet, index)

    with patch.object(PCAPParser, "_parse_single_packet", flaky_parse):
        result = parser.parse()

    assert len(result) == 2


def test_parse_empty_pcap_returns_empty_list(tmp_path):
    pcap_file = tmp_path / "empty.pcap"
    wrpcap(str(pcap_file), [])

    parser = PCAPParser(pcap_file)
    result = parser.parse()

    assert result == []


# ---------------------------------------------------------------------------
# _extract_dns_answers() testleri
#
# DNS cevaplarındaki A/AAAA kayıtlarından (IP -> sorgulanan domain) eşlemesi
# çıkarılır. Rapordaki "hangi IP hangi alan adına aitti" bilgisi buradan gelir,
# dolayısıyla bozuk/eksik cevaplarda istisna fırlatmak yerine sessizce boş
# dönmesi kritik: tek bir garip DNS paketi tüm ayrıştırmayı düşürmemeli.
# ---------------------------------------------------------------------------

def _dns_response(qname="example.com", rdata="93.184.216.34", rtype=1):
    """A/AAAA cevabı içeren bir DNS yanıt paketi üretir."""
    from scapy.all import DNSQR, DNSRR

    return (
        Ether()
        / IP(src="10.0.0.53", dst="10.0.0.1")
        / UDP(sport=53, dport=40000)
        / DNS(
            id=1,
            qr=1,
            qd=DNSQR(qname=qname),
            an=DNSRR(rrname=qname, type=rtype, rdata=rdata),
            ancount=1,
        )
    )


def test_extract_dns_answers_returns_ip_to_domain_mapping(dummy_parser):
    answers = dummy_parser._extract_dns_answers(_dns_response())

    assert answers == (("93.184.216.34", "example.com"),)


def test_extract_dns_answers_strips_trailing_dot_from_qname(dummy_parser):
    """Scapy qname'i 'example.com.' olarak verir; sondaki nokta atılmalı.

    Aksi halde aynı alan adı raporda iki farklı anahtar gibi görünür.
    """
    answers = dummy_parser._extract_dns_answers(_dns_response(qname="example.com."))

    assert answers[0][1] == "example.com"


def test_extract_dns_answers_ignores_queries_without_answers(dummy_parser):
    """Sorgu paketinde (qr=0) henüz cevap yoktur."""
    from scapy.all import DNSQR

    query = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.53")
        / UDP(sport=40000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )

    assert dummy_parser._extract_dns_answers(query) == ()


def test_extract_dns_answers_returns_empty_for_non_dns_packet(dummy_parser):
    assert dummy_parser._extract_dns_answers(make_tcp_packet()) == ()


def test_extract_dns_answers_skips_non_address_record_types(dummy_parser):
    """A/AAAA dışındaki kayıtlar (ör. CNAME) IP eşlemesi üretmez."""
    answers = dummy_parser._extract_dns_answers(
        _dns_response(rdata="alias.example.com", rtype=5)
    )

    assert answers == ()


# ---------------------------------------------------------------------------
# _extract_dns_query_info() testleri
# ---------------------------------------------------------------------------

def test_extract_dns_query_info_returns_name_and_type(dummy_parser):
    from scapy.all import DNSQR

    packet = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.53")
        / UDP(sport=40000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="tunnel.example.com", qtype="TXT"))
    )

    name, qtype = dummy_parser._extract_dns_query_info(packet)

    assert name == "tunnel.example.com"
    assert qtype == "TXT"


def test_extract_dns_query_info_maps_unknown_qtype_to_its_number(dummy_parser):
    """Bilinmeyen kayıt tipi düşürülmemeli; sayısal değeriyle korunmalı."""
    from scapy.all import DNSQR

    packet = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.53")
        / UDP(sport=40000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com", qtype=99))
    )

    _, qtype = dummy_parser._extract_dns_query_info(packet)

    assert qtype == "99"


def test_extract_dns_query_info_returns_none_for_non_dns_packet(dummy_parser):
    assert dummy_parser._extract_dns_query_info(make_tcp_packet()) == (None, None)


def test_extract_dns_query_info_returns_none_when_question_section_missing(dummy_parser):
    packet = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.53")
        / UDP(sport=40000, dport=53)
        / DNS(rd=1, qd=None)
    )

    assert dummy_parser._extract_dns_query_info(packet) == (None, None)


# ---------------------------------------------------------------------------
# Port tabanlı uygulama protokolü tespiti
#
# Scapy katmanı tanımadığında port numarasına düşülür.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("sport", "dport", "transport", "expected"),
    [
        (40000, 22, "TCP", "SSH"),
        (40000, 21, "TCP", "FTP"),
        (20, 40000, "TCP", "FTP"),
        (68, 67, "UDP", "DHCP"),
        (40000, 123, "UDP", "NTP"),
        (40000, 161, "UDP", "SNMP"),
        (162, 40000, "UDP", "SNMP"),
    ],
)
def test_extract_application_protocol_falls_back_to_well_known_ports(
    dummy_parser, sport, dport, transport, expected
):
    packet = make_tcp_packet(sport=sport, dport=dport)
    result = dummy_parser._extract_application_protocol(packet, sport, dport, transport)

    assert result == expected


def test_extract_application_protocol_returns_none_for_unknown_ports(dummy_parser):
    packet = make_tcp_packet(sport=40000, dport=41000)

    assert dummy_parser._extract_application_protocol(packet, 40000, 41000, "TCP") is None


# ---------------------------------------------------------------------------
# Akış düzeyinde hata: dosya bozuksa fail-fast
# ---------------------------------------------------------------------------

def test_parse_raises_runtime_error_when_stream_is_corrupt(tmp_path):
    """Paket düzeyinde hata tolere edilir, AKIŞ düzeyinde hata edilmez.

    Bozuk bir dosyadan yarım bir paket listesi döndürmek adli açıdan
    tehlikelidir: analist eksik veriyi tam sanır. Bu yüzden akış hatası
    RuntimeError'a çevrilip yukarı fırlatılır.
    """
    corrupt = tmp_path / "corrupt.pcap"
    corrupt.write_bytes(b"bunlar gecerli bir pcap baslik degil" * 4)

    parser = PCAPParser(corrupt)

    with pytest.raises(RuntimeError, match="PCAP okuma hatası"):
        parser.parse()


# ---------------------------------------------------------------------------
# Bellek: tekrar eden string alanlarının paylaşılması
#
# Bir capture'da src_ip/dst_ip/protokol/bayrak alanları küçük bir değer
# kümesinden gelir ama milyonlarca pakette tekrarlanır. Scapy her paket için
# ayrı str nesnesi ürettiğinden, intern edilmezlerse aynı metin milyonlarca
# kez kopyalanır. Ölçüm: 300 bin pakette tutulan bellek 428 -> 291 bayt/paket
# (%32 azalma). Bu testler optimizasyonun sessizce geri alınmasını engeller.
# ---------------------------------------------------------------------------

def test_repeated_string_fields_share_one_object(tmp_path):
    """Aynı değere sahip alanlar TEK bir nesneyi paylaşmalı (kopyalanmamalı)."""
    pcap_file = tmp_path / "shared.pcap"
    packets = [make_tcp_packet(src="10.0.0.1", dst="10.0.0.2", flags="PA") for _ in range(50)]
    wrpcap(str(pcap_file), packets)

    parsed = PCAPParser(pcap_file).parse()

    assert len(parsed) == 50
    for field in ("src_ip", "dst_ip", "network_protocol", "transport_protocol", "tcp_flags"):
        object_ids = {id(getattr(p, field)) for p in parsed}
        assert len(object_ids) == 1, (
            f"{field}: 50 pakette {len(object_ids)} ayrı nesne var; "
            "intern edilmemiş, bellek boşa harcanıyor"
        )


def test_ip_fields_are_plain_str_not_scapy_subclass(tmp_path):
    """IP alanları düz str olmalı, Scapy'nin _ScopedIP alt sınıfı değil.

    Scapy IP adreslerini str'den TÜREYEN bir tiple döndürüyor. sys.intern
    alt sınıfları reddettiği için ('can't intern _ScopedIP') düz str'e
    indirgenmeleri gerekiyor; bu indirgeme atlanırsa ayrıştırma TypeError
    ile çöker.
    """
    pcap_file = tmp_path / "plain.pcap"
    wrpcap(str(pcap_file), [make_tcp_packet(), make_ipv6_packet()])

    parsed = PCAPParser(pcap_file).parse()

    for p in parsed:
        assert type(p.src_ip) is str, f"src_ip düz str değil: {type(p.src_ip)}"
        assert type(p.dst_ip) is str, f"dst_ip düz str değil: {type(p.dst_ip)}"


def test_interning_preserves_field_values(tmp_path):
    """Bellek optimizasyonu değerleri DEĞİŞTİRMEMELİ (ör. IPv6 kısaltmaları)."""
    pcap_file = tmp_path / "values.pcap"
    wrpcap(str(pcap_file), [make_tcp_packet(src="192.168.1.50", dst="8.8.8.8", flags="S")])

    parsed = PCAPParser(pcap_file).parse()

    assert parsed[0].src_ip == "192.168.1.50"
    assert parsed[0].dst_ip == "8.8.8.8"
    assert parsed[0].transport_protocol == "TCP"


def test_large_capture_logs_warning_but_still_parses(tmp_path, monkeypatch, caplog):
    """Eşik aşıldığında uyarı loglanmalı ama analiz REDDEDİLMEMELİ.

    Adli bir araçta büyük bir delil dosyasını işlemeyi reddetmek kabul edilemez;
    amaç yalnızca, bellek yetmezse analistin sebebini bilmesi.
    """
    pcap_file = tmp_path / "big.pcap"
    wrpcap(str(pcap_file), [make_tcp_packet() for _ in range(5)])
    # Eşiği dosyanın altına çekerek "büyük dosya" durumunu taklit et.
    monkeypatch.setattr(config, "LARGE_CAPTURE_WARNING_BYTES", 1)

    with caplog.at_level(logging.WARNING):
        parsed = PCAPParser(pcap_file).parse()

    assert len(parsed) == 5, "uyarıya rağmen ayrıştırma tamamlanmalı"
    assert "Büyük capture" in caplog.text
    assert "RAM" in caplog.text


def test_normal_capture_does_not_log_size_warning(tmp_path, caplog):
    pcap_file = tmp_path / "small.pcap"
    wrpcap(str(pcap_file), [make_tcp_packet()])

    with caplog.at_level(logging.WARNING):
        PCAPParser(pcap_file).parse()

    assert "Büyük capture" not in caplog.text
