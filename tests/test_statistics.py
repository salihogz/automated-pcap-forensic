import config
from modules.models import PacketInfo
from modules.statistics import build_general_statistics


def _make_packet(epoch_time, src_ip, dst_ip, length, transport="TCP",
                  src_port=12345, dst_port=80, packet_id=0):
    return PacketInfo(
        id=packet_id,
        epoch_time=epoch_time,
        src_ip=src_ip,
        dst_ip=dst_ip,
        is_ipv6=False,
        network_protocol="IPv4",
        transport_protocol=transport,
        application_protocol="HTTP",
        length=length,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags="A",
    )


def test_empty_packet_list_returns_zero_stats():
    stats = build_general_statistics([])
    assert stats.total_packets == 0
    assert stats.first_packet_time is None


def test_total_packets_and_bytes():
    packets = [
        _make_packet(1.0, "10.0.0.1", "10.0.0.2", 100),
        _make_packet(2.0, "10.0.0.1", "10.0.0.3", 200),
    ]
    stats = build_general_statistics(packets)
    assert stats.total_packets == 2
    assert stats.total_bytes == 300
    assert stats.first_packet_time == 1.0
    assert stats.last_packet_time == 2.0
    assert stats.capture_duration == 1.0


def test_top_bandwidth_hosts_counts_bytes_not_packets():
    packets = [
        _make_packet(1.0, "10.0.0.1", "10.0.0.2", 1000),
        _make_packet(2.0, "10.0.0.9", "10.0.0.9", 1),
    ]
    stats = build_general_statistics(packets)

    # Host bandwidth hem gelen hem giden trafiği (src + dst) toplar:
    # 10.0.0.1 -> 1000 byte (src)
    # 10.0.0.2 -> 1000 byte (dst)
    # 10.0.0.9 -> 2 byte (1 src + 1 dst)
    assert stats.top_bandwidth_hosts == [
        ("10.0.0.1", 1000),
        ("10.0.0.2", 1000),
        ("10.0.0.9", 2),
    ]


def test_udp_ports_counts_both_src_and_dst():
    # DNS-benzeri senaryo: kaynak port 53 (yanıt), hedef port yüksek port
    packets = [
        _make_packet(1.0, "8.8.8.8", "10.0.0.5", 100,
                     transport="UDP", src_port=53, dst_port=51000),
    ]
    stats = build_general_statistics(packets)
    ports = dict(stats.top_udp_ports)
    assert ports[53] == 1
    assert ports[51000] == 1


def test_timeline_uses_epoch_based_buckets():
    bucket_size = getattr(config, "TIMELINE_BUCKET_SECONDS", 1.0)

    t0 = 100.0
    t1 = t0 + (bucket_size * 0.4)  # t0 ile aynı bucket
    t2 = t0 + (bucket_size * 1.2)  # bir sonraki bucket

    packets = [
        _make_packet(t0, "10.0.0.1", "10.0.0.2", 50),
        _make_packet(t1, "10.0.0.1", "10.0.0.2", 50),
        _make_packet(t2, "10.0.0.1", "10.0.0.2", 50),
    ]
    stats = build_general_statistics(packets)

    bucket_1_key = (t0 // bucket_size) * bucket_size
    bucket_2_key = (t2 // bucket_size) * bucket_size

    assert stats.timeline[bucket_1_key] == 2
    assert stats.timeline[bucket_2_key] == 1


def test_invalid_timestamp_excluded_from_time_calculations():
    packets = [
        _make_packet(0.0, "10.0.0.1", "10.0.0.2", 100),    # bozuk timestamp
        _make_packet(50.0, "10.0.0.1", "10.0.0.3", 200),   # geçerli
        _make_packet(52.0, "10.0.0.1", "10.0.0.4", 300),   # geçerli
    ]
    stats = build_general_statistics(packets)
    assert stats.total_packets == 3           # bozuk paket sayıma dahil
    assert stats.total_bytes == 600            # bozuk paketin byte'ı da dahil
    assert stats.first_packet_time == 50.0     # ama zaman hesabına dahil değil
    assert stats.last_packet_time == 52.0
    assert stats.capture_duration == 2.0


def _layered_packet(packet_id, network, transport, application):
    """Katman protokolleri serbestçe verilebilen paket üreticisi."""
    return PacketInfo(
        id=packet_id,
        epoch_time=1000.0 + packet_id,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        is_ipv6=False,
        network_protocol=network,
        transport_protocol=transport,
        application_protocol=application,
        length=100,
        src_port=None,
        dst_port=None,
        tcp_flags=None,
    )


def test_protocol_distribution_falls_back_to_network_layer():
    """Taşıma katmanı olmayan paketler ağ katmanı adıyla sayılmalı.

    Regresyon: birleşik dağılım yalnızca
    `application_protocol or transport_protocol or "UNKNOWN"` zincirini
    kullanıyordu. Taşıma katmanı bulunmayan paketler bu yüzden "UNKNOWN"
    kovasına düşüyordu; en görünür kurbanı ARP'tı. Parser ARP'ı ağ katmanında
    doğru tespit ettiği hâlde, rapordaki protokol grafiğinde ARP diye bir şey
    görünmüyor, gerçek bir LAN capture'ının en yaygın protokollerinden biri
    "UNKNOWN" olarak kayboluyordu. Aynısı tanınmayan taşıma protokolleri
    (GRE/ESP/AH) için de geçerliydi.
    """
    packets = [
        _layered_packet(1, "ARP", None, None),
        _layered_packet(2, "ARP", None, None),
        _layered_packet(3, "IPv4", "TCP", "TLS"),
        _layered_packet(4, "IPv4", "ICMP", None),
        _layered_packet(5, "IPv4", None, None),  # GRE/ESP gibi tanınmayan taşıma
    ]

    dist = build_general_statistics(packets).protocol_distribution

    assert dist["ARP"] == 2
    assert dist["TLS"] == 1
    assert dist["ICMP"] == 1
    assert dist["IPv4"] == 1
    assert "UNKNOWN" not in dist
    # Birleşik dağılım her paketi TAM OLARAK bir kez saymalı.
    assert sum(dist.values()) == len(packets)
