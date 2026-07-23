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
    assert stats.capture_duration == 1.0


def test_top_bandwidth_hosts_counts_bytes_not_packets():
    packets = [
        _make_packet(1.0, "10.0.0.1", "10.0.0.2", 1000),
        _make_packet(2.0, "10.0.0.9", "10.0.0.9", 1),
    ]
    stats = build_general_statistics(packets)
    top_ip, top_bytes = stats.top_bandwidth_hosts[0]
    assert top_ip == "10.0.0.1"
    assert top_bytes == 1000


def test_tcp_ports_counts_both_src_and_dst():
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
    packets = [
        _make_packet(100.0, "10.0.0.1", "10.0.0.2", 50),
        _make_packet(100.4, "10.0.0.1", "10.0.0.2", 50),
        _make_packet(101.2, "10.0.0.1", "10.0.0.2", 50),
    ]
    stats = build_general_statistics(packets)
    # bucket_seconds=1 varsayımıyla: 100.0 ve 100.4 aynı bucket'a düşer
    assert stats.timeline[100.0] == 2
    assert stats.timeline[101.0] == 1


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