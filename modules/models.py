# modules/models.py
"""
Automated PCAP Forensic Analysis Tool - Data Models
Proje genelinde kullanılan veri yapılarını (Dataclass) barındırır.
"""
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple


@dataclass(slots=True)
class PacketInfo:
    """
    Ayrıştırılan her bir paketi temsil eden immutable veri sınıfı.
    `slots=True` kullanımı bellek tüketimini minimize eder.
    """
    id: int
    epoch_time: float
    src_ip: Optional[str]
    dst_ip: Optional[str]
    is_ipv6: bool
    network_protocol: str                  # IPv4 / IPv6 / ARP / OTHER
    transport_protocol: Optional[str]       # TCP / UDP / ICMP / None
    application_protocol: Optional[str]     # DNS / HTTP / TLS / DHCP / SSH / FTP / NTP / SNMP / None
    length: int
    src_port: Optional[int]
    dst_port: Optional[int]
    tcp_flags: Optional[str]

    def to_dict(self) -> dict:
        """Nesneyi dictionary yapısına dönüştürür (Raporlama ve Jinja2 için)."""
        return asdict(self)


@dataclass(slots=True)
class GeneralStatistics:
    """
    General Statistics modülünün ürettiği özet istatistikleri temsil eder.
    Threat Detector ve Reporter modülleri bu veriyi tüketir.
    """
    total_packets: int
    total_bytes: int
    first_packet_time: Optional[float]
    last_packet_time: Optional[float]
    capture_duration: float

    protocol_distribution: Counter
    network_protocol_distribution: Counter
    transport_protocol_distribution: Counter
    application_protocol_distribution: Counter

    top_bandwidth_hosts: List[Tuple[str, int]]
    top_source_ips: List[Tuple[str, int]]
    top_destination_ips: List[Tuple[str, int]]
    top_tcp_ports: List[Tuple[int, int]]
    top_udp_ports: List[Tuple[int, int]]

    timeline: Dict[float, int]
