"""
modules/statistics.py

Parser'dan gelen paket akışını TEK GEÇİŞTE (single-pass) işleyerek
genel ağ trafiği istatistikleri üretir. Bu modül tehdit analizi
yapmaz; sadece sayar, gruplar ve özetler.

Performans notu:
Büyük pcap dosyalarında (milyonlarca paket) veriyi N kez dolaşmak
kabul edilemez maliyetli olduğundan, tüm sayaçlar tek bir for
döngüsü içinde birlikte güncellenir. Karmaşıklık O(N)'dir.

Veri kalitesi notu:
Parser, hatalı/okunamayan timestamp'lere sahip paketleri epoch_time=0.0
(1 Ocak 1970) olarak işaretleyip listede tutar (bkz. parser.py,
_parse_single_packet). Bu paketler total_packets/total_bytes sayımına
dahil edilir, ancak first/last time, capture_duration ve timeline
hesaplarına dahil EDİLMEZ. Aksi halde tek bir bozuk paket, capture
süresini 50+ yıla sıçratıp tüm zaman bazlı istatistikleri anlamsız
hale getirir.
"""

from __future__ import annotations

from collections import Counter
from typing import Iterable, Optional

import config
from modules.models import GeneralStatistics, PacketInfo


def build_general_statistics(packets: Iterable[PacketInfo]) -> GeneralStatistics:
    """
    Tüm genel istatistiklerin üretildiği ana giriş noktası.

    Iterable kabul eder (List değil) çünkü parser ileride streaming
    (generator/yield) mimarisine geçerse bu fonksiyonun değişmesine
    gerek kalmaz.
    """
    total_packets = 0
    total_bytes = 0
    first_time: Optional[float] = None
    last_time: Optional[float] = None
    timeline_reference_time: Optional[float] = None

    protocol_counter: Counter = Counter()
    network_counter: Counter = Counter()
    transport_counter: Counter = Counter()
    application_counter: Counter = Counter()

    bandwidth_counter: Counter = Counter()
    src_ip_counter: Counter = Counter()
    dst_ip_counter: Counter = Counter()

    tcp_port_counter: Counter = Counter()
    udp_port_counter: Counter = Counter()

    timeline_counter: Counter = Counter()

    for packet in packets:
        total_packets += 1
        total_bytes += packet.length

        # epoch_time == 0.0, parser'ın bozuk/okunamayan timestamp'ler
        # için verdiği sentinel değerdir (bkz. parser.py). Böyle bir
        # paket zaman bazlı hesaplara (first/last/duration/timeline)
        # dahil edilmez; aksi halde tüm capture süresi anlamsızlaşır.
        has_valid_time = packet.epoch_time > 0

        # --- Zaman sınırları ---
        if has_valid_time:
            if first_time is None or packet.epoch_time < first_time:
                first_time = packet.epoch_time
            if last_time is None or packet.epoch_time > last_time:
                last_time = packet.epoch_time

        # --- Dağılımlar ---
        protocol_counter[packet.application_protocol or packet.transport_protocol or "UNKNOWN"] += 1
        network_counter[packet.network_protocol or "UNKNOWN"] += 1
        transport_counter[packet.transport_protocol or "UNKNOWN"] += 1
        application_counter[packet.application_protocol or "UNKNOWN"] += 1

        # --- Bandwidth (byte bazlı) ---
        bandwidth_counter[packet.src_ip] += packet.length
        bandwidth_counter[packet.dst_ip] += packet.length

        # --- Paket sayısı bazlı IP istatistikleri ---
        src_ip_counter[packet.src_ip] += 1
        dst_ip_counter[packet.dst_ip] += 1

        # --- Portlar: hem kaynak hem hedef sayılır ---
        if packet.transport_protocol == "TCP":
            _increment_port(tcp_port_counter, packet.src_port)
            _increment_port(tcp_port_counter, packet.dst_port)
        elif packet.transport_protocol == "UDP":
            _increment_port(udp_port_counter, packet.src_port)
            _increment_port(udp_port_counter, packet.dst_port)

        # --- Timeline ---
        # PCAP dosyaları kronolojik yazıldığı için görülen ilk GEÇERLİ
        # zamanlı paket, referans (t=0) olarak kabul edilir.
        if has_valid_time:
            if timeline_reference_time is None:
                timeline_reference_time = packet.epoch_time

            offset = packet.epoch_time - timeline_reference_time
            bucket_index = int(offset // config.TIMELINE_BUCKET_SECONDS)
            bucket_time = timeline_reference_time + (bucket_index * config.TIMELINE_BUCKET_SECONDS)
            timeline_counter[bucket_time] += 1

    if total_packets == 0:
        return _empty_statistics()

    return GeneralStatistics(
        total_packets=total_packets,
        total_bytes=total_bytes,
        first_packet_time=first_time,
        last_packet_time=last_time,
        capture_duration=round(last_time - first_time, 6) if first_time is not None and last_time is not None else 0.0,
        protocol_distribution=protocol_counter,
        network_protocol_distribution=network_counter,
        transport_protocol_distribution=transport_counter,
        application_protocol_distribution=application_counter,
        top_bandwidth_hosts=bandwidth_counter.most_common(config.TOP_N_TALKERS),
        top_source_ips=src_ip_counter.most_common(config.TOP_N_IPS),
        top_destination_ips=dst_ip_counter.most_common(config.TOP_N_IPS),
        top_tcp_ports=tcp_port_counter.most_common(config.TOP_N_PORTS),
        top_udp_ports=udp_port_counter.most_common(config.TOP_N_PORTS),
        timeline=dict(sorted(timeline_counter.items())),
    )


def _increment_port(counter: Counter, port: Optional[int]) -> None:
    """Port None değilse sayaca ekler (DNS/NTP gibi UNKNOWN portları filtreler)."""
    if port is not None:
        counter[port] += 1


def _empty_statistics() -> GeneralStatistics:
    """Boş paket akışı için güvenli varsayılan değerler."""
    return GeneralStatistics(
        total_packets=0,
        total_bytes=0,
        first_packet_time=None,
        last_packet_time=None,
        capture_duration=0.0,
        protocol_distribution=Counter(),
        network_protocol_distribution=Counter(),
        transport_protocol_distribution=Counter(),
        application_protocol_distribution=Counter(),
        top_bandwidth_hosts=[],
        top_source_ips=[],
        top_destination_ips=[],
        top_tcp_ports=[],
        top_udp_ports=[],
        timeline={},
    )