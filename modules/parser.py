# modules/parser.py
"""
Automated PCAP Forensic Analysis Tool - PCAP Parser Module
PcapReader akış mimarisi, UTC epoch zaman damgası ve Dataclass veri yapısı ile PCAP çözümleme.
"""

import logging
from pathlib import Path

# Scapy standart katmanları
from scapy.all import ARP, DHCP, DNS, ICMP, IP, NTP, SNMP, TCP, UDP, IPv6, PcapReader
from scapy.packet import Packet

# TLS katmanını güvenli içe aktarma
try:
    from scapy.layers.tls.all import TLS
except (ImportError, ModuleNotFoundError):
    TLS = None

# HTTP katmanını güvenli içe aktarma (modül seviyesinde - performans için;
# her paket için tekrar tekrar import edilmesin diye TLS ile aynı desen).
try:
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
except (ImportError, ModuleNotFoundError):
    HTTP = None
    HTTPRequest = None
    HTTPResponse = None

import config
from modules.models import PacketInfo

logger = logging.getLogger(__name__)


class PCAPParser:
    """PCAP/PCAPNG dosyalarını çözerek PacketInfo nesnelerine dönüştüren kütüphane sınıfı."""

    def __init__(self, file_path: str | Path):
        self.file_path = Path(file_path)

    def validate_file(self) -> None:
        """Dosya geçerliliğini denetler; hata durumunda Exception fırlatır (Fail-Fast)."""
        if not self.file_path.exists():
            raise FileNotFoundError(f"PCAP dosyası bulunamadı: {self.file_path}")
        if not self.file_path.is_file():
            raise ValueError(f"Belirtilen yol geçerli bir dosya değil: {self.file_path}")
        if self.file_path.suffix.lower() not in config.SUPPORTED_EXTENSIONS:
            raise ValueError(
                f"Desteklenmeyen dosya formatı: {self.file_path.suffix}. "
                f"Desteklenenler: {config.SUPPORTED_EXTENSIONS}"
            )

    @staticmethod
    def _extract_network_layer(packet: Packet) -> tuple[str | None, str | None, str, bool]:
        """(src_ip, dst_ip, network_protocol, is_ipv6) çıkarır."""
        ip_layer = packet.getlayer(IP)
        if ip_layer is not None:
            return ip_layer.src, ip_layer.dst, "IPv4", False

        ipv6_layer = packet.getlayer(IPv6)
        if ipv6_layer is not None:
            return ipv6_layer.src, ipv6_layer.dst, "IPv6", True

        arp_layer = packet.getlayer(ARP)
        if arp_layer is not None:
            return arp_layer.psrc, arp_layer.pdst, "ARP", False

        return None, None, config.UNKNOWN_PROTOCOL, False

    @staticmethod
    def _extract_application_protocol(
        packet: Packet,
        src_port: int | None,
        dst_port: int | None
    ) -> str | None:
        """Uygulama katmanı protokolünü tespit eder (Scapy katmanları ve port fallback)."""
        if packet.haslayer(DNS):
            return "DNS"
        if packet.haslayer(DHCP):
            return "DHCP"
        if packet.haslayer(NTP):
            return "NTP"
        if packet.haslayer(SNMP):
            return "SNMP"
        if TLS is not None and packet.haslayer(TLS):
            return "TLS"
        if HTTP is not None and (
            packet.haslayer(HTTP) or packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse)
        ):
            return "HTTP"

        ports = {src_port, dst_port} - {None}
        if 53 in ports:
            return "DNS"
        if 80 in ports or 8080 in ports:
            return "HTTP"
        if 443 in ports or 8443 in ports:
            return "TLS"
        if 22 in ports:
            return "SSH"
        if 21 in ports or 20 in ports:
            return "FTP"
        if 67 in ports or 68 in ports:
            return "DHCP"
        if 123 in ports:
            return "NTP"
        if 161 in ports or 162 in ports:
            return "SNMP"

        return None

    @staticmethod
    def _extract_tcp_flags(tcp_layer: TCP) -> str:
        """TCP bayraklarını metne dönüştürür."""
        try:
            flags = str(tcp_layer.flags)
            return flags if flags else config.DEFAULT_FLAGS
        except (AttributeError, ValueError):
            return config.DEFAULT_FLAGS

    def _parse_single_packet(self, packet: Packet, index: int) -> PacketInfo:
        """Tek bir Scapy paketini PacketInfo dataclass modeline dönüştürür."""
        try:
            epoch_time = float(packet.time)
        except (ValueError, OverflowError, OSError, TypeError) as e:
            logger.warning("Paket #%d için hatalı timestamp atlandı: %s", index, e)
            epoch_time = 0.0

        src_ip, dst_ip, network_protocol, is_ipv6 = self._extract_network_layer(packet)

        transport_protocol: str | None = None
        src_port: int | None = None
        dst_port: int | None = None
        tcp_flags: str | None = None

        tcp_layer = packet.getlayer(TCP)
        if tcp_layer is not None:
            transport_protocol = "TCP"
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            tcp_flags = self._extract_tcp_flags(tcp_layer)
        else:
            udp_layer = packet.getlayer(UDP)
            if udp_layer is not None:
                transport_protocol = "UDP"
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
            else:
                icmp_layer = packet.getlayer(ICMP)
                if icmp_layer is not None:
                    transport_protocol = "ICMP"

        application_protocol = self._extract_application_protocol(packet, src_port, dst_port)

        return PacketInfo(
            id=index,
            epoch_time=epoch_time,
            src_ip=src_ip,
            dst_ip=dst_ip,
            is_ipv6=is_ipv6,
            network_protocol=network_protocol,
            transport_protocol=transport_protocol,
            application_protocol=application_protocol,
            length=len(packet),
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags,
        )

    def parse(self) -> list[PacketInfo]:
        """PCAP dosyasını PcapReader ile akış halinde okur ve PacketInfo listesi döndürür."""
        self.validate_file()
        logger.info("PCAP akış okuması başlatılıyor: %s", self.file_path.name)
        parsed_packets: list[PacketInfo] = []
        packet_count = 0
        try:
            with PcapReader(str(self.file_path)) as reader:
                for packet in reader:
                    packet_count += 1
                    try:
                        parsed_packets.append(self._parse_single_packet(packet, packet_count))
                    except Exception as pkt_err:
                        logger.warning("Paket #%d işlenirken hata oluştu, atlanıyor: %s", packet_count, pkt_err)
        except Exception as stream_err:
            logger.error("PCAP okuma akışı kritik hatayla kesildi: %s", stream_err)
            raise RuntimeError(f"PCAP okuma hatası: {stream_err}") from stream_err

        logger.info(
            "Ayrıştırma başarıyla tamamlandı. Toplam %d / %d paket işlendi.",
            len(parsed_packets), packet_count,
        )
        return parsed_packets