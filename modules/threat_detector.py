# modules/threat_detector.py
"""
Automated PCAP Forensic Analysis Tool - Threat Detector Engine
Kural tabanlı tehdit tespit motoru.
"""

import ipaddress
import logging
import math
from collections import defaultdict
from collections.abc import Iterable

import config
from modules.models import GeneralStatistics, PacketInfo, ThreatFinding, ThreatSeverity

logger = logging.getLogger(__name__)


class ThreatDetector:
    """Paket akışını analiz ederek adli bilişim bulguları üreten kural motoru."""

    def __init__(self, statistics: GeneralStatistics | None = None) -> None:
        self.statistics = statistics

    def detect(self, packets: Iterable[PacketInfo]) -> list[ThreatFinding]:
        """Verilen paket akışı üzerinde tüm tehdit tespit kurallarını çalıştırır."""
        findings: list[ThreatFinding] = []

        # Jeneratör/iteratör tipindeki girdileri tek seferlik listeye dönüştürür
        packet_list = list(packets)
        if not packet_list:
            logger.info("Tehdit tespiti için paket bulunamadı (boş liste).")
            return findings

        logger.info("Tehdit tespit motoru başlatılıyor. Paket sayısı: %d", len(packet_list))

        findings.extend(self._detect_port_scan(packet_list))
        findings.extend(self._detect_syn_scan(packet_list))
        findings.extend(self._detect_icmp_flood(packet_list))
        findings.extend(self._detect_failed_tcp_connections(packet_list))
        findings.extend(self._detect_dns_tunneling(packet_list))
        findings.extend(self._detect_long_domains(packet_list))
        findings.extend(self._detect_dga_domains(packet_list))
        findings.extend(self._detect_exfiltration(packet_list))

        logger.info("Tehdit tespiti tamamlandı. Toplam %d bulgu üretildi.", len(findings))
        return findings

    @staticmethod
    def _is_valid_transport_packet(packet: PacketInfo) -> bool:
        """Taşıma katmanı tespiti (Port Scan vb.) için paketin uygunluğunu kontrol eder."""
        if packet.src_ip is None or packet.dst_ip is None:
            return False
        if packet.dst_port is None or packet.dst_port <= 0:
            return False
        if packet.epoch_time is None or packet.epoch_time <= 0:
            return False
        if packet.transport_protocol not in ("TCP", "UDP"):
            return False
        return True

    @staticmethod
    def _is_egress_traffic(src_ip: str, dst_ip: str) -> bool:
        """Trafiğin iç ağdan genel (public) ağa doğru olup olmadığını denetler."""
        try:
            src_obj = ipaddress.ip_address(src_ip)
            dst_obj = ipaddress.ip_address(dst_ip)
            return (not src_obj.is_global) and dst_obj.is_global
        except ValueError:
            return False

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Verilen metnin Shannon entropisini hesaplar."""
        if not text:
            return 0.0
        length = len(text)
        counts: dict[str, int] = defaultdict(int)
        for char in text:
            counts[char] += 1
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _collect_unique_query_domains(packets: list[PacketInfo]) -> dict[str, list[PacketInfo]]:
        """Sorgulanan domain adlarına göre paketleri gruplar."""
        domains_map: dict[str, list[PacketInfo]] = defaultdict(list)
        for pkt in packets:
            if pkt.dns_query_name:
                domains_map[pkt.dns_query_name].append(pkt)
        return domains_map

    @staticmethod
    def _scan_window_for_threshold(
        ip_pair: tuple[str, str],
        packets_for_pair: list[PacketInfo],
        time_window: int,
        port_threshold: int,
        rule_id: str,
        title: str,
        severity: ThreatSeverity,
        description_fmt: str,
    ) -> list[ThreatFinding]:
        """Aynı IP çifti için zaman penceresindeki port kümesini tarar ve bulgu üretir."""
        findings: list[ThreatFinding] = []
        if not packets_for_pair:
            return findings

        # Zaman sırasına göre sırala
        sorted_pkts = sorted(packets_for_pair, key=lambda p: p.epoch_time)
        src_ip, dst_ip = ip_pair

        left = 0
        n = len(sorted_pkts)

        # Kayan pencere içindeki port sayıları ve ilk görülme zamanları
        port_counts: dict[int, int] = defaultdict(int)

        while left < n:
            window_start_time = sorted_pkts[left].epoch_time
            window_end_time = window_start_time + time_window

            port_counts.clear()

            right = left
            while right < n and sorted_pkts[right].epoch_time < window_end_time:
                pkt = sorted_pkts[right]
                if pkt.dst_port is not None:
                    port_counts[pkt.dst_port] += 1
                right += 1

            distinct_ports = set(port_counts.keys())
            if len(distinct_ports) >= port_threshold:
                window_packets = sorted_pkts[left:right]
                window_ports = [p.dst_port for p in window_packets if p.dst_port is not None]
                first_seen = window_packets[0].epoch_time
                last_seen = window_packets[-1].epoch_time

                sampled_ports = sorted(distinct_ports)[:10]

                finding = ThreatFinding(
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    description=description_fmt.format(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        count=len(distinct_ports),
                        time_window=time_window,
                    ),
                    evidence={
                        "distinct_port_count": len(distinct_ports),
                        "time_window_seconds": time_window,
                        "first_seen_epoch": first_seen,
                        "last_seen_epoch": last_seen,
                        "sampled_ports": sampled_ports,
                        "total_packets_in_window": len(window_packets),
                        "transport_protocols": sorted(
                            {p.transport_protocol for p in window_packets if p.transport_protocol}
                        ),
                    },
                    source=src_ip,
                    destination=dst_ip,
                    timestamp=first_seen,
                )
                findings.append(finding)

                # Bulgu üretildikten sonra aynı pencere/olay için tekrar çakışan
                # bulgular üretmemek adına pointer'ı pencere dışına kaydır
                left = right
            else:
                left += 1

        return findings

    def _detect_port_scan(self, packets: list[PacketInfo]) -> list[ThreatFinding]:
        """Aynı kaynak IP'nin aynı hedefe kısa sürede çok sayıda farklı portla erişimini tespit eder."""
        logger.info("Port Scan kuralı çalıştırılıyor...")
        findings: list[ThreatFinding] = []

        time_window = config.PORT_SCAN_TIME_WINDOW_SECONDS
        port_threshold = config.PORT_SCAN_PORT_THRESHOLD

        # (src_ip, dst_ip) -> list[PacketInfo]
        pair_buckets: dict[tuple[str, str], list[PacketInfo]] = defaultdict(list)

        for pkt in packets:
            if self._is_valid_transport_packet(pkt):
                pair_buckets[(pkt.src_ip, pkt.dst_ip)].append(pkt)  # type: ignore[arg-type]

        for (src_ip, dst_ip), pair_packets in pair_buckets.items():
            unique_ports = {p.dst_port for p in pair_packets if p.dst_port is not None}
            if len(unique_ports) < port_threshold:
                continue

            scan_findings = self._scan_window_for_threshold(
                ip_pair=(src_ip, dst_ip),
                packets_for_pair=pair_packets,
                time_window=time_window,
                port_threshold=port_threshold,
                rule_id="SEC-PORT-SCAN-001",
                title="Port Taraması Tespiti (Port Scan)",
                severity=ThreatSeverity.HIGH,
                description_fmt=(
                    "{src_ip} adresinden {dst_ip} adresine {time_window} saniye "
                    "içinde {count} farklı porta erişim tespiti yapıldı."
                ),
            )
            findings.extend(scan_findings)

        logger.info("Port Scan kuralı tamamlandı. %d bulgu üretildi.", len(findings))
        return findings

    def _detect_syn_scan(self, packets: list[PacketInfo]) -> list[ThreatFinding]:
        """SYN taraması (Stealth Scan) tespiti yapar."""
        logger.info("SYN Scan kuralı çalıştırılıyor...")
        findings: list[ThreatFinding] = []

        time_window = config.SYN_SCAN_TIME_WINDOW_SECONDS
        port_threshold = config.SYN_SCAN_PORT_THRESHOLD

        pair_buckets: dict[tuple[str, str], list[PacketInfo]] = defaultdict(list)

        for pkt in packets:
            if self._is_valid_transport_packet(pkt) and pkt.transport_protocol == "TCP":
                if pkt.tcp_flags == "S":
                    pair_buckets[(pkt.src_ip, pkt.dst_ip)].append(pkt)  # type: ignore[arg-type]

        for (src_ip, dst_ip), pair_packets in pair_buckets.items():
            unique_ports = {p.dst_port for p in pair_packets if p.dst_port is not None}
            if len(unique_ports) < port_threshold:
                continue

            scan_findings = self._scan_window_for_threshold(
                ip_pair=(src_ip, dst_ip),
                packets_for_pair=pair_packets,
                time_window=time_window,
                port_threshold=port_threshold,
                rule_id="SEC-SYN-SCAN-001",
                title="SYN Taraması Tespiti (SYN Scan)",
                severity=ThreatSeverity.HIGH,
                description_fmt=(
                    "{src_ip} adresinden {dst_ip} adresine {time_window} saniye "
                    "içinde {count} farklı porta SYN taraması yapıldığı tespit edildi."
                ),
            )
            findings.extend(scan_findings)

        logger.info("SYN Scan kuralı tamamlandı. %d bulgu üretildi.", len(findings))
        return findings

    def _detect_icmp_flood(self, packets: list[PacketInfo]) -> list[ThreatFinding]:
        """ICMP Flood DoS/DDoS saldırılarını tespit eder."""
        logger.info("ICMP Flood kuralı çalıştırılıyor...")
        findings: list[ThreatFinding] = []

        time_window = config.ICMP_FLOOD_TIME_WINDOW_SECONDS
        threshold = config.ICMP_FLOOD_PACKET_THRESHOLD

        pair_buckets: dict[tuple[str, str], list[PacketInfo]] = defaultdict(list)

        for pkt in packets:
            if (
                pkt.transport_protocol == "ICMP"
                and pkt.src_ip
                and pkt.dst_ip
                and pkt.epoch_time
                and pkt.epoch_time > 0
            ):
                pair_buckets[(pkt.src_ip, pkt.dst_ip)].append(pkt)

        for (src_ip, dst_ip), icmp_pkts in pair_buckets.items():
            if len(icmp_pkts) < threshold:
                continue

            sorted_pkts = sorted(icmp_pkts, key=lambda p: p.epoch_time)
            left = 0
            n = len(sorted_pkts)

            while left < n:
                window_start = sorted_pkts[left].epoch_time
                window_end = window_start + time_window

                right = left
                while right < n and sorted_pkts[right].epoch_time < window_end:
                    right += 1

                count = right - left
                if count >= threshold:
                    window_pkts = sorted_pkts[left:right]
                    first_seen = window_pkts[0].epoch_time
                    last_seen = window_pkts[-1].epoch_time

                    finding = ThreatFinding(
                        rule_id="SEC-ICMP-FLOOD-001",
                        title="ICMP Flood Saldırısı Tespiti",
                        severity=ThreatSeverity.HIGH,
                        description=(
                            f"{src_ip} adresinden {dst_ip} adresine {time_window} saniye "
                            f"içinde {count} adet ICMP paketi gönderildi."
                        ),
                        evidence={
                            "packet_count": count,
                            "time_window_seconds": time_window,
                            "first_seen_epoch": first_seen,
                            "last_seen_epoch": last_seen,
                        },
                        source=src_ip,
                        destination=dst_ip,
                        timestamp=first_seen,
                    )
                    findings.append(finding)
                    left = right
                else:
                    left += 1

        logger.info("ICMP Flood kuralı tamamlandı. %d bulgu üretildi.", len(findings))
        return findings

    def _detect_failed_tcp_connections(self, packets: list[PacketInfo]) -> list[ThreatFinding]:
        """Tamamlanamayan / başarısız TCP bağlantılarını tespit eder."""
        logger.info("Failed TCP Connections kuralı çalıştırılıyor...")
        findings: list[ThreatFinding] = []

        time_window = config.FAILED_TCP_TIME_WINDOW_SECONDS
        threshold = config.FAILED_TCP_ATTEMPT_THRESHOLD

        # (src_ip, dst_ip) -> list[PacketInfo]
        ip_pair_buckets: dict[tuple[str, str], list[PacketInfo]] = defaultdict(list)

        for pkt in packets:
            if (
                pkt.transport_protocol == "TCP"
                and pkt.src_ip
                and pkt.dst_ip
                and pkt.dst_port
                and pkt.epoch_time
                and pkt.epoch_time > 0
            ):
                ip_pair_buckets[(pkt.src_ip, pkt.dst_ip)].append(pkt)

        for (src_ip, dst_ip), tcp_pkts in ip_pair_buckets.items():
            # Tamamlanamayan SYN paketlerini belirle
            syn_dict: dict[tuple[int, int], list[PacketInfo]] = defaultdict(list)
            syn_ack_ports: set[tuple[int, int]] = set()

            for pkt in tcp_pkts:
                flags = pkt.tcp_flags or ""
                key = (pkt.src_port or 0, pkt.dst_port or 0)
                reverse_key = (pkt.dst_port or 0, pkt.src_port or 0)

                if flags == "S":
                    syn_dict[key].append(pkt)
                elif "S" in flags and "A" in flags:
                    syn_ack_ports.add(reverse_key)

            failed_syn_pkts: list[PacketInfo] = []
            for key, pkts in syn_dict.items():
                if key not in syn_ack_ports:
                    failed_syn_pkts.extend(pkts)

            if len(failed_syn_pkts) < threshold:
                continue

            sorted_failed = sorted(failed_syn_pkts, key=lambda p: p.epoch_time)
            left = 0
            n = len(sorted_failed)

            while left < n:
                window_start = sorted_failed[left].epoch_time
                window_end = window_start + time_window

                right = left
                while right < n and sorted_failed[right].epoch_time < window_end:
                    right += 1

                count = right - left
                if count >= threshold:
                    window_pkts = sorted_failed[left:right]
                    first_seen = window_pkts[0].epoch_time
                    last_seen = window_pkts[-1].epoch_time
                    target_ports = sorted({p.dst_port for p in window_pkts if p.dst_port})[:10]

                    finding = ThreatFinding(
                        rule_id="SEC-FAILED-TCP-001",
                        title="Yüksek Başarısız TCP Bağlantı Denemesi",
                        severity=ThreatSeverity.MEDIUM,
                        description=(
                            f"{src_ip} adresinden {dst_ip} adresine {time_window} saniye "
                            f"içinde {count} adet başarısız TCP bağlantı denemesi tespiti."
                        ),
                        evidence={
                            "failed_attempt_count": count,
                            "time_window_seconds": time_window,
                            "first_seen_epoch": first_seen,
                            "last_seen_epoch": last_seen,
                            "sampled_target_ports": target_ports,
                        },
                        source=src_ip,
                        destination=dst_ip,
                        timestamp=first_seen,
                    )
                    findings.append(finding)
                    left = right
                else:
                    left += 1

        logger.info("Failed TCP Connections kuralı tamamlandı. %d bulgu üretildi.", len(findings))
        return findings

    def _detect_dns_tunneling(self, packets: list[PacketInfo]) -> list[ThreatFinding]:
        """DNS Tünelleme (DNS Tunneling) şüphesini tespit eder."""
        logger.info("DNS Tunneling kuralı çalıştırılıyor...")
        findings: list[ThreatFinding] = []

        time_window = config.DNS_TUNNEL_TIME_WINDOW_SECONDS
        query_threshold = config.DNS_TUNNEL_QUERY_COUNT_THRESHOLD
        suspicious_qtypes = set(config.DNS_TUNNEL_SUSPICIOUS_QTYPES)

        # (src_ip, base_domain) -> list[PacketInfo]
        domain_buckets: dict[tuple[str, str], list[PacketInfo]] = defaultdict(list)

        for pkt in packets:
            if pkt.application_protocol == "DNS" and pkt.dns_query_name and pkt.src_ip:
                parts = pkt.dns_query_name.split(".")
                base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else pkt.dns_query_name
                domain_buckets[(pkt.src_ip, base_domain)].append(pkt)

        for (src_ip, base_domain), dns_pkts in domain_buckets.items():
            if len(dns_pkts) < query_threshold:
                continue

            sorted_pkts = sorted(dns_pkts, key=lambda p: p.epoch_time)
            left = 0
            n = len(sorted_pkts)

            while left < n:
                window_start = sorted_pkts[left].epoch_time
                window_end = window_start + time_window

                right = left
                while right < n and sorted_pkts[right].epoch_time < window_end:
                    right += 1

                count = right - left
                if count >= query_threshold:
                    window_pkts = sorted_pkts[left:right]
                    suspicious_count = sum(
                        1 for p in window_pkts if p.dns_query_type in suspicious_qtypes
                    )

                    first_seen = window_pkts[0].epoch_time
                    last_seen = window_pkts[-1].epoch_time
                    sampled_queries = [p.dns_query_name for p in window_pkts[:5] if p.dns_query_name]

                    finding = ThreatFinding(
                        rule_id="SEC-DNS-TUNNEL-001",
                        title="Şüpheli DNS Tünelleme Tespiti",
                        severity=ThreatSeverity.CRITICAL,
                        description=(
                            f"{src_ip} adresi üzerinden {base_domain} alan adı için {time_window} "
                            f"saniyede {count} adet DNS sorgusu (şüpheli tip sayısı: {suspicious_count}) tespiti."
                        ),
                        evidence={
                            "base_domain": base_domain,
                            "query_count": count,
                            "suspicious_qtype_count": suspicious_count,
                            "time_window_seconds": time_window,
                            "first_seen_epoch": first_seen,
                            "last_seen_epoch": last_seen,
                            "sampled_queries": sampled_queries,
                        },
                        source=src_ip,
                        destination=None,
                        timestamp=first_seen,
                    )
                    findings.append(finding)
                    left = right
                else:
                    left += 1

        logger.info("DNS Tunneling kuralı tamamlandı. %d bulgu üretildi.", len(findings))
        return findings

    def _detect_long_domains(self, packets: list[PacketInfo]) -> list[ThreatFinding]:
        """Aşırı uzun alan adı (Long Domain) sorgularını tespit eder."""
        logger.info("Long Domain kuralı çalıştırılıyor...")
        findings: list[ThreatFinding] = []

        domains_map = self._collect_unique_query_domains(packets)
        long_domains_evidence: list[dict[str, float | str | int]] = []

        for domain, domain_pkts in domains_map.items():
            if len(domain) > config.LONG_DOMAIN_LENGTH:
                first_pkt = min(domain_pkts, key=lambda p: p.epoch_time)
                long_domains_evidence.append({
                    "domain": domain,
                    "length": len(domain),
                    "src_ip": first_pkt.src_ip or "UNKNOWN",
                    "timestamp": first_pkt.epoch_time,
                })

        if long_domains_evidence:
            first_seen = min(cast(float, item["timestamp"]) for item in long_domains_evidence)
            finding = ThreatFinding(
                rule_id="SEC-LONG-DOMAIN-001",
                title="Anormal Uzunlukta Alan Adı Sorguları Tespiti",
                severity=ThreatSeverity.LOW,
                description=(
                    f"Aşırı uzun ({config.LONG_DOMAIN_LENGTH} karakter üzeri) "
                    f"toplam {len(long_domains_evidence)} adet DNS sorgusu tespit edildi."
                ),
                evidence={
                    "total_long_domains": len(long_domains_evidence),
                    "domains": long_domains_evidence[:10],
                },
                source="VARIOUS",
                destination=None,
                timestamp=first_seen,
            )
            findings.append(finding)

        logger.info("Long Domain kuralı tamamlandı. %d bulgu üretildi.", len(findings))
        return findings

    def _detect_dga_domains(self, packets: list[PacketInfo]) -> list[ThreatFinding]:
        """Yüksek entropili DGA (Domain Generation Algorithm) alan adlarını tespit eder."""
        logger.info("DGA Detection kuralı çalıştırılıyor...")
        findings: list[ThreatFinding] = []

        domains_map = self._collect_unique_query_domains(packets)
        dga_evidence: list[dict[str, float | str]] = []

        for domain, domain_pkts in domains_map.items():
            parts = domain.split(".")
            label = parts[0] if parts else domain

            if len(label) >= config.DGA_MIN_LABEL_LENGTH:
                entropy = self._shannon_entropy(label)
                if entropy >= config.DGA_ENTROPY_THRESHOLD:
                    first_pkt = min(domain_pkts, key=lambda p: p.epoch_time)
                    dga_evidence.append({
                        "domain": domain,
                        "label": label,
                        "entropy": round(entropy, 2),
                        "src_ip": first_pkt.src_ip or "UNKNOWN",
                        "timestamp": first_pkt.epoch_time,
                    })

        if dga_evidence:
            first_seen = min(cast(float, item["timestamp"]) for item in dga_evidence)
            finding = ThreatFinding(
                rule_id="SEC-DGA-001",
                title="Şüpheli DGA Alan Adı Tespiti",
                severity=ThreatSeverity.HIGH,
                description=(
                    f"Yüksek entropi gösteren ({config.DGA_ENTROPY_THRESHOLD} ve üzeri) "
                    f"toplam {len(dga_evidence)} adet DGA şüpheli alan adı tespit edildi."
                ),
                evidence={
                    "total_dga_domains": len(dga_evidence),
                    "domains": dga_evidence[:10],
                },
                source="VARIOUS",
                destination=None,
                timestamp=first_seen,
            )
            findings.append(finding)

        logger.info("DGA Detection kuralı tamamlandı. %d bulgu üretildi.", len(findings))
        return findings

    def _detect_exfiltration(self, packets: list[PacketInfo]) -> list[ThreatFinding]:
        """Aşırı dışa veri aktarımı (Data Exfiltration) durumlarını tespit eder."""
        logger.info("Exfiltration kuralı çalıştırılıyor...")
        findings: list[ThreatFinding] = []

        # (src_ip, dst_ip) -> total_bytes, first_seen, last_seen
        exfil_map: dict[tuple[str, str], dict[str, float | int]] = defaultdict(
            lambda: {"total_bytes": 0, "first_seen": float("inf"), "last_seen": 0.0}
        )

        for pkt in packets:
            if pkt.src_ip and pkt.dst_ip and self._is_egress_traffic(pkt.src_ip, pkt.dst_ip):
                entry = exfil_map[(pkt.src_ip, pkt.dst_ip)]
                entry["total_bytes"] += pkt.length
                if pkt.epoch_time < entry["first_seen"]:
                    entry["first_seen"] = pkt.epoch_time
                if pkt.epoch_time > entry["last_seen"]:
                    entry["last_seen"] = pkt.epoch_time

        threshold = config.EXFILTRATION_THRESHOLD

        for (src_ip, dst_ip), data in exfil_map.items():
            total_bytes = cast(int, data["total_bytes"])
            if total_bytes >= threshold:
                first_seen = cast(float, data["first_seen"])
                last_seen = cast(float, data["last_seen"])
                mb_size = total_bytes / (1024 * 1024)

                finding = ThreatFinding(
                    rule_id="SEC-EXFIL-001",
                    title="Yüksek Hacimli Veri Sızdırma (Data Exfiltration) Tespiti",
                    severity=ThreatSeverity.CRITICAL,
                    description=(
                        f"{src_ip} iç IP adresinden {dst_ip} dış IP adresine {mb_size:.2f} MB "
                        "boyutunda şüpheli veri aktarımı tespiti yapıldı."
                    ),
                    evidence={
                        "total_bytes": total_bytes,
                        "total_megabytes": round(mb_size, 2),
                        "threshold_bytes": threshold,
                        "first_seen_epoch": first_seen,
                        "last_seen_epoch": last_seen,
                    },
                    source=src_ip,
                    destination=dst_ip,
                    timestamp=first_seen,
                )
                findings.append(finding)

        logger.info("Exfiltration kuralı tamamlandı. %d bulgu üretildi.", len(findings))
        return findings


from typing import cast