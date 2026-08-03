# modules/models.py
"""
Automated PCAP Forensic Analysis Tool - Data Models
Proje genelinde kullanılan veri yapılarını (Dataclass) barındırır.
"""
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


@dataclass(frozen=True, slots=True)
class PacketInfo:
    """
    Ayrıştırılan her bir paketi temsil eden immutable veri sınıfı.

    `slots=True` bellek tüketimini azaltır.
    `frozen=True` ise paket oluşturulduktan sonra alanlarının
    değiştirilememesini garanti eder (adli veri bütünlüğü/chain of custody
    açısından önemlidir).
    """
    id: int
    epoch_time: float
    src_ip: str | None
    dst_ip: str | None
    is_ipv6: bool
    network_protocol: str                  # IPv4 / IPv6 / ARP / OTHER
    transport_protocol: str | None       # TCP / UDP / ICMP / None
    application_protocol: str | None     # DNS / HTTP / TLS / DHCP / SSH / FTP / NTP / SNMP / None
    length: int
    src_port: int | None
    dst_port: int | None
    tcp_flags: str | None

    # Bu paket bir DNS YANITI ise, yanıttaki A/AAAA cevap kayıtlarından
    # türetilen (ip, sorgulanan_hostname) ikilileri. DNS yanıtı değilse
    # veya çözümlenebilir bir A/AAAA kaydı yoksa boş tuple. Immutable
    # tuple kullanılır (liste değil) çünkü PacketInfo frozen'dır ve
    # varsayılan değer tüm örnekler arasında güvenle paylaşılabilmelidir.
    dns_answers: tuple[tuple[str, str], ...] = ()

    def to_dict(self) -> dict:
        """Nesneyi dictionary yapısına dönüştürür (Raporlama ve Jinja2 için)."""
        return asdict(self)


class ThreatSeverity(str, Enum):
    """
    Tehdit seviyelerini belirten Enum sınıfı.
    str kalıtımı sayesinde JSON/HTML serileştirmede kolaylık sağlar.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True, slots=True)
class ThreatFinding:
    """
    Tehdit tespit motoru tarafından üretilen tekil bulguyu temsil eder.

    frozen=True: Bir bulgu üretildikten sonra değiştirilemez
    (chain of custody / veri bütünlüğü).

    Attributes:
        rule_id: Kuralın benzersiz kimliği (Örn: SEC-RULE-001).
        title: Tehdidin kısa başlığı.
        severity: Tehdit önem derecesi (ThreatSeverity Enum).
        description: Detaylı açıklama ve adli analiz notu.
        evidence: Kurala özel kanıt verileri (Örn: taranan port sayısı, domain listesi).
        source: Tehdit kaynağı olan IP/Host.
        destination: Hedef IP/Host (Opsiyonel).
        timestamp: Tespiti tetikleyen ilk veya son olayın epoch zamanı.
    """
    rule_id: str
    title: str
    severity: ThreatSeverity
    description: str
    evidence: dict[str, Any]
    source: str
    destination: str | None = None
    timestamp: float | None = None

    def to_dict(self) -> dict:
        """Nesneyi dictionary yapısına dönüştürür (Raporlama ve Jinja2 için)."""
        return asdict(self)


@dataclass(slots=True)
class GeneralStatistics:
    """
    General Statistics modülünün ürettiği özet istatistikleri temsil eder.
    Threat Detector ve Reporter modülleri bu veriyi tüketir.

    NOT: Dağılım alanları (protocol_distribution vb.) bilinçli olarak
    `dict[str, int]` tipindedir, `Counter[str]` DEĞİL. statistics.py bu
    alanları hesaplarken Counter kullanabilir, ama dataclass'a atarken
    `dict(counter)` ile sade dict'e çevirmelidir. Aksi halde
    `dataclasses.asdict()` (to_dict / Jinja2 raporlama) Counter'ı
    yanlış yeniden inşa eder ve veriyi bozar.
    """
    total_packets: int
    total_bytes: int
    first_packet_time: float | None
    last_packet_time: float | None
    capture_duration: float

    protocol_distribution: dict[str, int]
    network_protocol_distribution: dict[str, int]
    transport_protocol_distribution: dict[str, int]
    application_protocol_distribution: dict[str, int]

    top_bandwidth_hosts: list[tuple[str, int]]
    top_source_ips: list[tuple[str, int]]
    top_destination_ips: list[tuple[str, int]]
    top_tcp_ports: list[tuple[int, int]]
    top_udp_ports: list[tuple[int, int]]

    timeline: dict[float, int]

    # IP -> hostname eşlemesi. DNS yanıt paketlerinden (soru adı + A/AAAA
    # cevap kaydı) türetilir. Bir IP için birden çok hostname görülürse en
    # sık geçen seçilir (bkz. statistics.py). Eşleşmesi olmayan IP'ler bu
    # sözlükte YER ALMAZ (raporlama katmanı .get(ip) ile sorgular).
    # Varsayılan None + __post_init__ kullanılıyor çünkü sabit mutable
    # default (dict) tüm örnekler arasında paylaşılır; bu ayrıca eski
    # GeneralStatistics(...) çağrılarıyla (testlerde konumsal/anahtar
    # sözcüklü, bu alan olmadan) geriye dönük uyumluluğu korur.
    ip_hostname_map: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if self.ip_hostname_map is None:
            self.ip_hostname_map = {}

    def to_dict(self) -> dict:
        """Nesneyi dictionary yapısına dönüştürür (Raporlama ve Jinja2 için)."""
        return asdict(self)