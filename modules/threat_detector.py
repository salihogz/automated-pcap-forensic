"""
threat_detector.py - Tehdit Tespit Motoru Framework'ü

Bu modül, paket akışını (PacketInfo) veya genel istatistikleri (GeneralStatistics)
analiz ederek güvenlik olaylarını ve anormallikleri tespit eder.
"""

import logging
from collections import Counter, defaultdict
from collections.abc import Iterable
from operator import itemgetter

import config
from modules.models import (
    GeneralStatistics,
    PacketInfo,
    ThreatFinding,
    ThreatSeverity,
)

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
        findings.extend(self._detect_port_scan(packet_list))

        logger.info("ThreatDetector: Analiz tamamlandı. Toplam %d bulgu üretildi.", len(findings))
        return findings

    @staticmethod
    def _is_valid_transport_packet(packet: PacketInfo) -> bool:
        """
        Paketin TCP/UDP analizine uygun olup olmadığını doğrulayan yardımcı koruyucu.
        Parser'ın protokol isimlerini büyük harfe normalize ettiği varsayılmıştır.
        """
        if not packet.transport_protocol or packet.transport_protocol not in ("TCP", "UDP"):
            return False

        if not packet.src_ip or not packet.dst_ip or packet.dst_port is None:
            return False

        if packet.dst_port <= 0:
            return False

        return packet.epoch_time is not None and packet.epoch_time > 0

    def _detect_port_scan(self, packets: list[PacketInfo]) -> list[ThreatFinding]:
        """
        Port Scan tespiti: bir (src_ip, dst_ip) çifti için zaman penceresi
        içindeki farklı hedef port sayısı eşiği aşarsa bulgu üretir.
        """
        findings: list[ThreatFinding] = []

        threshold = config.PORT_SCAN_PORT_THRESHOLD
        time_window = config.PORT_SCAN_TIME_WINDOW_SECONDS

        # 1. Gruplama: (src_ip, dst_ip) -> [(epoch_time, dst_port), ...]
        connections: defaultdict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)

        for packet in packets:
            if not self._is_valid_transport_packet(packet):
                continue

            key = (packet.src_ip, packet.dst_ip)
            connections[key].append((packet.epoch_time, packet.dst_port))

        # 2. Her grup için kayan pencere taraması
        for (src_ip, dst_ip), events in connections.items():
            unique_ports = {port for _, port in events}
            if len(unique_ports) < threshold:
                continue

            events.sort(key=itemgetter(0))

            group_findings = self._scan_window_for_threshold(
                src_ip, dst_ip, events, time_window, threshold
            )
            findings.extend(group_findings)

        return findings

    @staticmethod
    def _scan_window_for_threshold(
        src_ip: str,
        dst_ip: str,
        sorted_events: list[tuple[float, int]],
        time_window: float,
        threshold: int,
    ) -> list[ThreatFinding]:
        """
        Zamana göre sıralanmış (epoch_time, dst_port) olayları üzerinde
        two-pointer kayan pencere uygular.
        """
        findings: list[ThreatFinding] = []
        port_counter: Counter[int] = Counter()
        left = 0

        for right, (right_time, right_port) in enumerate(sorted_events):
            port_counter[right_port] += 1

            # Pencereyi zaman sınırının içinde tutmak için soldan daralt.
            while right_time - sorted_events[left][0] > time_window:
                _, left_port = sorted_events[left]
                port_counter[left_port] -= 1
                if port_counter[left_port] == 0:
                    del port_counter[left_port]
                left += 1

            distinct_port_count = len(port_counter)
            if distinct_port_count >= threshold:
                window_start_time = sorted_events[left][0]
                window_end_time = right_time

                # --- DFIR & DEBUG LOGGING ---
                logger.info(
                    "Port scan detected: %s -> %s (%d ports)",
                    src_ip,
                    dst_ip,
                    distinct_port_count,
                )

                findings.append(
                    ThreatFinding(
                        rule_id="SEC-PORT-SCAN-001",
                        title="Port Scan Tespit Edildi",
                        severity=ThreatSeverity.HIGH,
                        description=(
                            f"{src_ip} kaynağından {dst_ip} hedefine, "
                            f"{time_window} saniyelik zaman "
                            f"penceresi içinde {distinct_port_count} farklı porta "
                            f"bağlantı denemesi tespit edildi (eşik: "
                            f"{threshold})."
                        ),
                        evidence={
                            "distinct_port_count": distinct_port_count,
                            "threshold": threshold,
                            "time_window_seconds": time_window,
                            "scanned_ports": sorted(port_counter.keys()),
                            "window_start_time": window_start_time,
                            "window_end_time": window_end_time,
                        },
                        source=src_ip,
                        destination=dst_ip,
                        timestamp=window_end_time,
                    )
                )

                # Tespit sonrası pencereyi sıfırla
                while left <= right:
                    _, left_port = sorted_events[left]
                    port_counter[left_port] -= 1
                    if port_counter[left_port] == 0:
                        del port_counter[left_port]
                    left += 1

        return findings