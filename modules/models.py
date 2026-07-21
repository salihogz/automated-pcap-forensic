# modules/models.py
"""
Automated PCAP Forensic Analysis Tool - Data Models
Proje genelinde kullanılan veri yapılarını (Dataclass) barındırır.
"""

from dataclasses import dataclass, asdict
from typing import Optional


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
    transport_protocol: Optional[str]      # TCP / UDP / ICMP / None
    application_protocol: Optional[str]    # DNS / HTTP / TLS / DHCP / SSH / FTP / NTP / SNMP / None
    length: int
    src_port: Optional[int]
    dst_port: Optional[int]
    tcp_flags: Optional[str]

    def to_dict(self) -> dict:
        """Nesneyi dictionary yapısına dönüştürür (Raporlama ve Jinja2 için)."""
        return asdict(self)