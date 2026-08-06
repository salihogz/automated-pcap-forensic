# modules/parser.py
"""
Automated PCAP Forensic Analysis Tool - PCAP Parser Module
PcapReader akış mimarisi, UTC epoch zaman damgası ve Dataclass veri yapısı ile PCAP çözümleme.
"""

import logging
import sys
from pathlib import Path

# Scapy standart katmanları
from scapy.all import ARP, DHCP, DNS, ICMP, IP, NTP, SNMP, TCP, UDP, IPv6, PcapReader
from scapy.error import Scapy_Exception
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


def _intern(value: str | None) -> str | None:
    """Metni intern eder (None ise dokunmaz).

    İki incelik var:

    1. Bu alanların hepsi opsiyoneldir (ör. ICMP paketinde tcp_flags None'dır),
       bu yüzden None kontrolü gerekli.
    2. `str(value)` çağrısı gereksiz görünse de zorunludur: Scapy IP adreslerini
       düz str değil, str'den TÜREYEN `_ScopedIP` olarak döndürür. sys.intern
       alt sınıfları reddeder ("can't intern _ScopedIP"), dolayısıyla önce düz
       str'e indirgenmeleri gerekir. Bu indirgeme ayrıca alt sınıf sarmalayıcısının
       ek yükünü de ortadan kaldırır.
    """
    if isinstance(value, str):
        return sys.intern(str(value))
    return value


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

        self._warn_if_large()

    def _warn_if_large(self) -> None:
        """Çok büyük capture'larda bellek kullanımı hakkında uyarır.

        Ayrıştırma akış halinde yapılır ama PacketInfo nesnelerinin tamamı
        bellekte tutulur (tespit kuralları capture'ın bütününe bakar). Analiz
        REDDEDİLMEZ: meşru büyük capture'ları engellemek adli bir araçta kabul
        edilemez. Amaç yalnızca, işlem OOM ile aniden kesilirse analistin
        sebebini bilmesi.

        Uyarı tek bir sayı yerine ARALIK verir. Bellek paket sayısıyla orantılı
        olduğundan, aynı dosya boyutu paket boyutuna göre çok farklı bellek
        gerektirir: minimum boyutlu (64 bayt) paketlerle dosya boyutunun ~5
        katı, büyük paketlerle ~0,15 katı. Tek bir kötümser çarpan basmak
        (önceki davranış) 1,3 GB'lık gerçek bir capture için "6513 MB
        gerekebilir" diyordu; gerçekte 179 MB kullanıldı. Bu 36 kat sapma,
        analisti gereksiz yere dosyayı bölmeye yönlendirir.
        """
        try:
            size_bytes = self.file_path.stat().st_size
        except OSError:  # pragma: no cover - stat burada pratikte başarısız olmaz
            return

        if size_bytes < config.LARGE_CAPTURE_WARNING_BYTES:
            return

        size_mb = size_bytes / (1024 * 1024)
        typical_mb = size_mb * config.LARGE_CAPTURE_TYPICAL_MEMORY_FACTOR
        worst_case_mb = size_mb * config.LARGE_CAPTURE_WORST_CASE_MEMORY_FACTOR
        logger.warning(
            "Büyük capture (%.0f MB). Paketlerin tamamı bellekte tutulur. "
            "Gereken RAM paket SAYISINA bağlıdır: büyük paketli bir capture'da "
            "~%.0f MB, yalnızca minimum boyutlu (64 bayt) paketlerden oluşan en "
            "kötü durumda ~%.0f MB. Bellek yetersiz kalırsa capture'ı editcap "
            "gibi bir araçla parçalara bölüp ayrı ayrı analiz edin.",
            size_mb,
            typical_mb,
            worst_case_mb,
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
        dst_port: int | None,
        transport_protocol: str | None,
    ) -> str | None:
        """Uygulama katmanı protokolünü tespit eder (Scapy katmanları ve port fallback).

        Port fallback'i `transport_protocol`'ü dikkate alır: HTTP/TLS/SSH/FTP
        yalnızca TCP üzerinde anlamlıdır. Bunun kontrol edilmemesi, günümüzde
        çok yaygın olan QUIC/HTTP3 trafiğini (UDP/443, örn. Cloudflare/Google
        CDN'leri) "TLS" olarak yanlış sınıflandırıyordu — TLS'in kendisi
        yalnızca TCP üzerinde koşar, QUIC ise kendi (UDP tabanlı) şifreleme
        katmanına sahiptir ve raporlarda ayrı bir protokol olarak görünmelidir.
        """
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
        is_tcp = transport_protocol == "TCP"

        if 53 in ports:
            return "DNS"
        if (443 in ports or 8443 in ports) and not is_tcp:
            return "QUIC"
        if (80 in ports or 8080 in ports) and is_tcp:
            return "HTTP"
        if (443 in ports or 8443 in ports) and is_tcp:
            return "TLS"
        if 22 in ports and is_tcp:
            return "SSH"
        if (21 in ports or 20 in ports) and is_tcp:
            return "FTP"
        if 67 in ports or 68 in ports:
            return "DHCP"
        if 123 in ports:
            return "NTP"
        if 161 in ports or 162 in ports:
            return "SNMP"

        return None

    # DNS resource record tipleri: A (IPv4) ve AAAA (IPv6). Sadece bu
    # tipler bir IP adresine karşılık gelir; CNAME/TXT/NS/MX gibi diğer
    # kayıt tipleri rdata alanında IP taşımaz, bu yüzden atlanır.
    _DNS_A_AAAA_TYPES = (1, 28)

    @staticmethod
    def _extract_dns_answers(packet: Packet) -> tuple[tuple[str, str], ...]:
        """DNS yanıt paketlerinden (ip, hostname) eşleşmelerini çıkarır.

        Hostname olarak orijinal SORU adı (qd.qname) kullanılır; bir yanıt
        CNAME zinciri içerse dahi (örn. www.site.com -> cdn.example.net ->
        1.2.3.4), rapor kullanıcısının asıl ilgilendiği "hangi domain bu
        trafiği tetikledi" sorusunun cevabı sorgulanan isimdir, ara CNAME
        değil. Yalnızca DNS YANITLARI (qr == 1) işlenir; sorgu paketlerinde
        henüz bir IP cevabı yoktur.
        """
        dns_layer = packet.getlayer(DNS)
        if dns_layer is None:
            return ()

        try:
            if dns_layer.qr != 1 or not dns_layer.ancount or dns_layer.qd is None:
                return ()
            query_name = dns_layer.qd.qname
            if isinstance(query_name, bytes):
                query_name = query_name.decode("utf-8", errors="ignore")
            query_name = query_name.rstrip(".")
            if not query_name:
                return ()
        except (AttributeError, IndexError, UnicodeDecodeError):
            return ()

        results: list[tuple[str, str]] = []
        for i in range(dns_layer.ancount):
            try:
                rr = dns_layer.an[i]
                if rr.type in PCAPParser._DNS_A_AAAA_TYPES and isinstance(rr.rdata, str):
                    results.append((rr.rdata, query_name))
            except (AttributeError, IndexError):
                continue

        return tuple(results)

    @staticmethod
    def _extract_dns_query_info(packet: Packet) -> tuple[str | None, str | None]:
        """DNS paketlerinden (query ve response) sorgulanan domain adı ve kayıt tipini çıkarır."""
        dns_layer = packet.getlayer(DNS)
        if dns_layer is None:
            return None, None

        try:
            if dns_layer.qd is None:
                return None, None

            query_name = dns_layer.qd.qname
            if isinstance(query_name, bytes):
                query_name = query_name.decode("utf-8", errors="ignore")
            query_name = query_name.rstrip(".")
            if not query_name:
                query_name = None

            # Haritada olmayan bir qtype sessizce kaybolmaz, ham sayısal
            # değeriyle korunur (kanıt kaybı olmaması için).
            qtype_val = dns_layer.qd.qtype
            query_type = (
                config.DNS_QTYPE_MAP.get(qtype_val, str(qtype_val))
                if qtype_val is not None
                else None
            )

            return query_name, query_type
        except (AttributeError, IndexError, UnicodeDecodeError):
            return None, None

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

        application_protocol = self._extract_application_protocol(
            packet, src_port, dst_port, transport_protocol
        )

        dns_answers = ()
        dns_query_name = None
        dns_query_type = None

        if application_protocol == "DNS":
            dns_answers = self._extract_dns_answers(packet)
            dns_query_name, dns_query_type = self._extract_dns_query_info(packet)

        return PacketInfo(
            id=index,
            epoch_time=epoch_time,
            # Bellek: bu alanlar milyonlarca pakette tekrar eden, küçük bir
            # değer kümesinden gelir (bir capture'da tipik olarak birkaç yüz
            # farklı IP, tek haneli sayıda protokol ve bayrak kombinasyonu).
            # Scapy her paket için AYRI bir str nesnesi ürettiğinden, intern
            # edilmezlerse aynı metin milyonlarca kez kopyalanır: 300 bin
            # paketlik bir ölçümde tutulan 121 MB'ın 76 MB'ı bu kopyalardı,
            # oysa benzersiz değerlerin toplamı 3 MB idi. _intern paylaşılan
            # tek bir nesneye işaret ettirir; PacketInfo frozen olduğu için
            # paylaşım güvenlidir.
            src_ip=_intern(src_ip),
            dst_ip=_intern(dst_ip),
            is_ipv6=is_ipv6,
            network_protocol=_intern(network_protocol),
            transport_protocol=_intern(transport_protocol),
            application_protocol=_intern(application_protocol),
            length=len(packet),
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=_intern(tcp_flags),
            dns_answers=dns_answers,
            dns_query_name=dns_query_name,
            dns_query_type=dns_query_type,
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
        except (Scapy_Exception, OSError, ValueError, TypeError) as stream_err:
            logger.error("PCAP okuma akışı kritik hatayla kesildi: %s", stream_err)
            raise RuntimeError(f"PCAP okuma hatası: {stream_err}") from stream_err

        logger.info(
            "Ayrıştırma başarıyla tamamlandı. Toplam %d / %d paket işlendi.",
            len(parsed_packets), packet_count,
        )
        return parsed_packets
