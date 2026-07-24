"""
threat_detector.py - Tehdit Tespit Motoru Framework'ü

Bu modül, paket akışını (PacketInfo) veya genel istatistikleri (GeneralStatistics)
analiz ederek güvenlik olaylarını ve anormallikleri tespit eder.
"""

import logging
from collections.abc import Iterable

from modules.models import GeneralStatistics, PacketInfo, ThreatFinding

logger = logging.getLogger(__name__)


class ThreatDetector:
    """
    Tehdit tespit kurallarını çalıştıran ve adli bulguları (ThreatFinding) üreten ana motor.
    """

    def __init__(self, stats: GeneralStatistics | None = None) -> None:
        """
        ThreatDetector başlatıcı.

        Args:
            stats: Önceden hesaplanmış genel istatistikler (opsiyonel).
                   Bazı kurallar doğrudan genel istatistikleri kullanabilir.
        """
        self.stats = stats

    def detect(self, packets: Iterable[PacketInfo]) -> list[ThreatFinding]:
        """
        Tüm aktif tespit kurallarını paketler üzerinde sırayla çalıştırır.

        Not: Parser modülü streaming (tek geçiş) mimarisi kullanır, ancak
        burada bilinçli olarak listeye çeviriyoruz. Çünkü birden fazla
        bağımsız kural (port scan, SYN scan, DNS tunneling vb.) aynı paket
        kümesi üzerinde ayrı ayrı gezinecek; generator tek kullanımlık
        olduğu için ikinci kural boş küme görürdü.

        Args:
            packets: İncelemeye tabi PacketInfo nesnelerinin akışı/listesi.

        Returns:
            Tespit edilen tüm tehditlerin list[ThreatFinding] listesi.
        """
        findings: list[ThreatFinding] = []

        packet_list = packets if isinstance(packets, list) else list(packets)
        if not packet_list:
            logger.warning("ThreatDetector: Analiz edilecek paket bulunamadı.")
            return findings

        logger.info(
            "ThreatDetector: %d paket üzerinde tespit kuralları çalıştırılıyor...",
            len(packet_list),
        )

        # --- TESPİT KURALLARI PİPELİNE ---
        # İlerleyen sprintlerde kurallar buraya eklenecektir:
        # findings.extend(self._detect_port_scan(packet_list))
        # findings.extend(self._detect_syn_scan(packet_list))
        # findings.extend(self._detect_icmp_flood(packet_list))
        # findings.extend(self._detect_dns_tunneling(packet_list))
        # findings.extend(self._detect_long_domains(packet_list))
        # findings.extend(self._detect_dga_domains(packet_list))
        # findings.extend(self._detect_large_transfer(packet_list))
        # findings.extend(self._detect_failed_connections(packet_list))

        logger.info("ThreatDetector: Analiz tamamlandı. Toplam %d bulgu üretildi.", len(findings))
        return findings