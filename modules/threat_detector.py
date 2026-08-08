# modules/threat_detector.py
"""
Automated PCAP Forensic Analysis Tool - Threat Detector Engine
Kural tabanlı tehdit tespit motoru.
"""

import ipaddress
import logging
import math
from bisect import bisect_left
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator
from typing import cast

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

        # Jeneratör/iteratör tipindeki girdiler listeye alınır: kurallar paket
        # listesini birden çok kez dolaşır, tek seferlik bir iteratör ilk
        # kuraldan sonra tükenmiş olurdu.
        #
        # Girdi ZATEN bir liste ise kopyalanmaz. `list(...)` içeriği değil
        # yalnızca işaretçileri kopyalar, ama bu bile paket başına 8 bayttır:
        # main.py'nin verdiği 10 milyon paketlik listede sırf bu kopya 80 MB
        # eder ve o sırada iki liste birden bellekte durur. PacketInfo frozen
        # olduğundan paylaşılan liste üzerinde çalışmak güvenlidir.
        packet_list = packets if isinstance(packets, list) else list(packets)
        if not packet_list:
            logger.info("Tehdit tespiti için paket bulunamadı (boş liste).")
            return findings

        logger.info("Tehdit tespit motoru başlatılıyor. Paket sayısı: %d", len(packet_list))

        # Long-domain ve DGA kurallarının ikisi de "sorgulanan alan adı ->
        # paketler" haritasına ihtiyaç duyar. Harita burada BİR KEZ kurulup
        # ikisine de verilir; daha önce her kural haritayı kendisi kuruyor,
        # yani paket listesi üzerinde iki tam geçiş yapılıp aynı içerikte iki
        # sözlük birden bellekte tutuluyordu.
        query_domains = self._collect_unique_query_domains(packet_list)

        findings.extend(self._detect_port_scan(packet_list))
        findings.extend(self._detect_syn_scan(packet_list))
        findings.extend(self._detect_syn_flood(packet_list))
        findings.extend(self._detect_icmp_flood(packet_list))
        findings.extend(self._detect_failed_tcp_connections(packet_list))
        findings.extend(self._detect_dns_tunneling(packet_list))
        findings.extend(self._detect_long_domains(packet_list, query_domains))
        findings.extend(self._detect_dga_domains(packet_list, query_domains))
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
        return packet.transport_protocol in ("TCP", "UDP")

    @staticmethod
    def _is_probable_response_packet(packet: PacketInfo) -> bool:
        """Paketin, bir isteğe verilen YANIT olma olasılığının yüksek olup
        olmadığını kestirir (servis portundan ephemeral porta giden trafik).

        Port taraması, tarayıcının ephemeral kaynak portundan hedefteki
        SERVİS portlarına doğru yapılır. Ters yön (servis portu -> ephemeral
        port) bir taramanın değil, normal bir istemci-sunucu diyaloğunun
        dönüş bacağıdır. `_detect_port_scan` yalnızca farklı `dst_port`
        saydığı için bu ayrım yapılmazsa, istemcinin her sorgusuna farklı
        bir ephemeral porttan cevap veren sıradan bir DNS sunucusu
        (53 -> 33615, 53 -> 38777, 53 -> 50922 ...) "onlarca farklı porta
        erişim" olarak okunur ve tamamen temiz bir capture yanlışlıkla
        HIGH severity port taraması bulgusu üretir.

        BİLİNEN SINIRLILIK: Kaynak portunu bilinçli olarak düşük bir servis
        portuna sabitleyen taramalar (ör. `nmap -g 53`, güvenlik duvarı
        atlatma amaçlı) bu filtre tarafından elenir. Bu, bilinçli bir
        değiş-tokuştur: söz konusu teknik nadirdir, buna karşılık filtrenin
        engellediği yanlış-pozitif (her DNS/NTP/QUIC yanıtı) her capture'da
        ortaya çıkar ve raporun risk seviyesini tümüyle anlamsızlaştırır.
        TCP tabanlı taramalar ayrıca `_detect_syn_scan` tarafından bayrak
        (flag) düzeyinde, bu filtreden bağımsız olarak yakalanmaya devam eder.
        """
        src_port = packet.src_port
        dst_port = packet.dst_port
        if src_port is None or dst_port is None:
            return False
        return src_port < config.EPHEMERAL_PORT_MIN <= dst_port

    @staticmethod
    def _is_egress_traffic(src_ip: str, dst_ip: str) -> bool:
        """Trafiğin iç ağdan genel (public) ağa doğru olup olmadığını denetler.

        `is_global` MULTICAST adresleri için de True döner (239.255.255.250
        SSDP, 224.0.0.251 mDNS, ff02::fb ...). Multicast bir dış hedef host
        DEĞİL, yerel ağın kendi içindeki bir dağıtım grubudur; oraya giden
        trafik ağdan hiç çıkmaz. Bu adresler ayrıca elenmezse, yüksek hacimli
        yerel yayın trafiği (ör. bir medya sunucusunun SSDP/DLNA duyuruları
        veya çok yayınlı video akışı) SEC-EXFIL-001 tarafından "dış IP'ye veri
        sızdırma" olarak CRITICAL severity ile raporlanır — raporun en ağır
        bulgusu tamamen yanlış-pozitif olur. Aynı eleme main.py'de dış Threat
        Intel sorguları için de yapılır (bkz. main._is_public_ip).
        """
        try:
            src_obj = ipaddress.ip_address(src_ip)
            dst_obj = ipaddress.ip_address(dst_ip)
        except ValueError:
            return False

        return (not src_obj.is_global) and dst_obj.is_global and not dst_obj.is_multicast

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
    def _compute_base_domain(query_name: str) -> str:
        """Bir DNS sorgu adından, gruplama için kullanılacak "temel alan adı"nı çıkarır.

        Naif yaklaşım sondan iki etiketi alır (`"sub.evil.com"` -> `"evil.com"`),
        ancak çok parçalı public suffix'lere sahip alan adlarında
        (`"sub.firma.com.tr"`, `"sub.firma.co.uk"`) bu, suffix'in kendisini
        ("com.tr", "co.uk") temel alan adı sanar; bunun sonucunda birbiriyle
        hiçbir ilgisi olmayan şirketlerin ".com.tr"/".co.uk" trafiği aynı
        (src_ip, base_domain) kovasında toplanır — hem yanlış-pozitif
        SEC-DNS-TUNNEL-001 bulgularına hem de bulgudaki `base_domain` kanıt
        alanının anlamsız bir suffix'e (ör. gerçek saldırgan alan adı yerine
        "com.tr") işaret etmesine yol açar.

        `config.DNS_TUNNEL_MULTI_LABEL_SUFFIXES` tam bir Public Suffix List
        (PSL) değildir — offline çalışma gereksinimi nedeniyle internetten
        PSL çekmek yerine en yaygın çok parçalı suffix'leri kapsayan küçük,
        statik bir tablo kullanılır. Tabloda olmayan bir suffix ile
        karşılaşılırsa eski (sondan-iki-etiket) davranışa sessizce geri döner.
        """
        parts = query_name.split(".")
        if len(parts) < 2:
            return query_name

        last_two = ".".join(parts[-2:])
        if len(parts) >= 3 and last_two in config.DNS_TUNNEL_MULTI_LABEL_SUFFIXES:
            return ".".join(parts[-3:])
        return last_two

    @staticmethod
    def _earliest_packet(packets: list[PacketInfo]) -> PacketInfo:
        """Listedeki en erken paketi döndürür; BOZUK zaman damgalarını atlar.

        Parser, okunamayan bir zaman damgasını `epoch_time=0.0` sentinel'i ile
        işaretleyip paketi listede tutar (bkz. parser._parse_single_packet).
        Düz bir `min(..., key=epoch_time)` bu sentinel'i her zaman "en erken"
        seçer; sonuçta bulgunun `timestamp` alanı ve kanıttaki "İlk Görülme"
        değeri raporda 1970-01-01 olarak görünür — capture'ın gerçek zamanıyla
        hiç ilgisi olmayan bir tarih. statistics.py aynı sentinel'i zaman bazlı
        hesaplardan zaten dışlıyor; bu yardımcı, aynı korumayı DNS tabanlı
        kurallara (long-domain, DGA) taşır.

        Hiç geçerli zamanlı paket yoksa elde olan en iyi veriye düşülür:
        bulgu üretilmemesindense 0.0 zamanlı bulgu üretmek yeğdir (kanıt kaybı
        olmaz, kural sessizce kaybolmaz).
        """
        valid = [p for p in packets if p.epoch_time > 0]
        return min(valid or packets, key=lambda p: p.epoch_time)

    @staticmethod
    def _collect_unique_query_domains(packets: list[PacketInfo]) -> dict[str, list[PacketInfo]]:
        """Sorgulanan domain adlarına göre paketleri gruplar."""
        domains_map: dict[str, list[PacketInfo]] = defaultdict(list)
        for pkt in packets:
            if pkt.dns_query_name:
                domains_map[pkt.dns_query_name].append(pkt)
        return domains_map

    @staticmethod
    def _slide_count_windows(
        sorted_pkts: list[PacketInfo],
        time_window: int,
        threshold: float,
        weight_fn: Callable[[PacketInfo], float] | None = None,
    ) -> Iterator[tuple[int, int]]:
        """Zamana göre sıralı bir paket listesi üzerinde kayan pencere
        taraması yapar; pencere içindeki toplam AĞIRLIK eşiği karşılarsa
        yarı-açık `[left, right)` indeks aralığını üretir (`sorted_pkts[left:right]`).

        `weight_fn` her paketin pencere toplamına ne kadar katkı yapacağını
        belirler; varsayılan `None` her paketi 1 olarak sayar (saf paket-sayım
        taraması — ICMP flood, failed-TCP, DNS tunneling bu şekilde kullanır).
        Exfiltration kuralı `weight_fn=lambda p: p.length` geçerek AYNI
        pencereleme mekanizmasını byte-toplamı taraması için yeniden kullanır
        (bkz. `_detect_exfiltration`) — mantığı iki kez yazmamak için.

        `right` işaretçisi tüm tarama boyunca yalnızca ileri gider ve hiçbir
        `left` adımında `left`'e sıfırlanmaz; bu yüzden toplam maliyet
        O(N)'dir. (ICMP flood, failed-TCP, DNS tunneling kuralları arasında
        paylaşılan bu döngünün eski, her-`left`-adımında-pencereyi-baştan-
        tarayan hali, tek bir zaman penceresinde binlerce paketin biriktiği
        yoğun trafikte O(N * pencere_boyutu)'ya -pratikte O(N^2)'ye-
        yaklaşıyordu.)
        """
        weight = weight_fn or (lambda _pkt: 1)
        left = 0
        right = 0
        n = len(sorted_pkts)
        window_weight = 0.0

        while left < n:
            window_end = sorted_pkts[left].epoch_time + time_window
            right = max(right, left)
            while right < n and sorted_pkts[right].epoch_time < window_end:
                window_weight += weight(sorted_pkts[right])
                right += 1

            if window_weight >= threshold:
                yield left, right
                for i in range(left, right):
                    window_weight -= weight(sorted_pkts[i])
                left = right
            else:
                window_weight -= weight(sorted_pkts[left])
                left += 1

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
        right = 0
        n = len(sorted_pkts)

        # Kayan pencere içindeki port sayıları. `right` tüm döngü boyunca
        # yalnızca ileri gider (asla `left`'e sıfırlanmaz) ve `left`
        # ilerlediğinde pencereden çıkan tek paket sayaçtan düşülür;
        # böylece toplam maliyet O(N) amortized kalır. Önceki sürüm her
        # `left` adımında pencereyi baştan tarıyordu (`right = left`),
        # bu da yoğun trafikte (tek pencerede binlerce paket) O(N*W)'ye,
        # pratikte O(N^2)'ye yaklaşan bir maliyete yol açıyordu.
        port_counts: dict[int, int] = defaultdict(int)

        def _add(idx: int) -> None:
            pkt = sorted_pkts[idx]
            if pkt.dst_port is not None:
                port_counts[pkt.dst_port] += 1

        def _remove(idx: int) -> None:
            pkt = sorted_pkts[idx]
            if pkt.dst_port is not None:
                port_counts[pkt.dst_port] -= 1
                if port_counts[pkt.dst_port] <= 0:
                    del port_counts[pkt.dst_port]

        while left < n:
            window_start_time = sorted_pkts[left].epoch_time
            window_end_time = window_start_time + time_window

            while right < n and sorted_pkts[right].epoch_time < window_end_time:
                _add(right)
                right += 1

            # `len(port_counts)` doğrudan okunur. Önceki sürüm her `left`
            # adımında `set(port_counts.keys())` ile YENİ bir küme kuruyordu;
            # bu, sadece sayıya bakmak için pencere başına O(k) kopyalama
            # demekti ve döngünün tamamını O(N*k)'ya çıkarıyordu (kuralın
            # tetiklenmediği yoğun trafik en kötü durum). Kümeyi yalnızca
            # gerçekten bir bulgu üretilirken -yani nadiren- kuruyoruz.
            if len(port_counts) >= port_threshold:
                distinct_ports = set(port_counts)
                window_packets = sorted_pkts[left:right]
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
                for i in range(left, right):
                    _remove(i)
                left = right
            else:
                _remove(left)
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
            # Yanıt trafiği (servis portu -> ephemeral port) taramaya değil,
            # normal bir diyaloğun dönüş bacağına aittir; sayıma alınırsa
            # her DNS/NTP/QUIC sunucusu "port tarayıcı" gibi görünür.
            if self._is_valid_transport_packet(pkt) and not self._is_probable_response_packet(pkt):
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
            if (
                self._is_valid_transport_packet(pkt)
                and pkt.transport_protocol == "TCP"
                and pkt.tcp_flags == "S"
            ):
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

    def _detect_syn_flood(self, packets: list[PacketInfo]) -> list[ThreatFinding]:
        """Tek bir hedef servise yönelen hacimsel SYN yoğunluğunu tespit eder.

        NEDEN AYRI BİR KURAL: Mevcut kuralların hiçbiri bu senaryoyu görmüyordu.
        `_detect_syn_scan` tek kaynaktan ÇOK SAYIDA FARKLI PORTA bakar; flood
        ise TEK PORTA yığılır, dolayısıyla o kuralın eşiğini hiç zorlamaz.
        `_detect_failed_tcp_connections` ise yalnızca YANITSIZ SYN'leri sayar;
        hedef SYN-ACK ile cevap veriyorsa (yani sunucu ayaktayken yapılan
        sıradan bir flood) hiçbir SYN "başarısız" görünmez. Sonuç, saniyede
        yüzlerce SYN alan bir servisin raporda hiç yer almamasıydı.

        HEDEFE göre gruplanır (kaynağa değil): flood'larda kaynak IP'ler
        genellikle sahtedir (spoofed) ve her paket farklı bir kaynaktan
        geliyormuş gibi görünür; kaynağa göre gruplamak saldırıyı binlerce
        tek paketlik kovaya bölerek görünmez kılardı.
        """
        logger.info("SYN Flood kuralı çalıştırılıyor...")
        findings: list[ThreatFinding] = []

        time_window = config.SYN_FLOOD_TIME_WINDOW_SECONDS
        threshold = config.SYN_FLOOD_PACKET_THRESHOLD

        # (dst_ip, dst_port) -> saf SYN paketleri
        target_buckets: dict[tuple[str, int], list[PacketInfo]] = defaultdict(list)

        for pkt in packets:
            if (
                pkt.transport_protocol == "TCP"
                and pkt.tcp_flags == "S"
                and pkt.dst_ip
                and pkt.dst_port
                and pkt.epoch_time > 0
            ):
                target_buckets[(pkt.dst_ip, pkt.dst_port)].append(pkt)

        for (dst_ip, dst_port), syn_pkts in target_buckets.items():
            if len(syn_pkts) < threshold:
                continue

            sorted_pkts = sorted(syn_pkts, key=lambda p: p.epoch_time)

            for left, right in self._slide_count_windows(sorted_pkts, time_window, threshold):
                window_pkts = sorted_pkts[left:right]
                count = len(window_pkts)
                sources = {p.src_ip for p in window_pkts if p.src_ip}
                first_seen = window_pkts[0].epoch_time
                last_seen = window_pkts[-1].epoch_time

                # Tek kaynaklı bir flood'da o kaynağı adlandırmak analiste
                # doğrudan bir pivot noktası verir; çok kaynaklıda "VARIOUS"
                # yazmak, uydurma bir tekil kaynak göstermekten dürüsttür.
                source = next(iter(sources)) if len(sources) == 1 else "VARIOUS"

                findings.append(
                    ThreatFinding(
                        rule_id="SEC-SYN-FLOOD-001",
                        title="TCP SYN Flood Saldırısı Tespiti",
                        severity=ThreatSeverity.HIGH,
                        description=(
                            f"{dst_ip}:{dst_port} hedefine {time_window} saniye içinde "
                            f"{count} adet TCP SYN paketi gönderildi "
                            f"({len(sources)} farklı kaynak IP)."
                        ),
                        evidence={
                            "packet_count": count,
                            "distinct_source_count": len(sources),
                            "target_port": dst_port,
                            "time_window_seconds": time_window,
                            "first_seen_epoch": first_seen,
                            "last_seen_epoch": last_seen,
                            "sampled_sources": sorted(sources)[:10],
                        },
                        source=source,
                        destination=dst_ip,
                        timestamp=first_seen,
                    )
                )

        logger.info("SYN Flood kuralı tamamlandı. %d bulgu üretildi.", len(findings))
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

            for left, right in self._slide_count_windows(sorted_pkts, time_window, threshold):
                window_pkts = sorted_pkts[left:right]
                count = len(window_pkts)
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

        logger.info("ICMP Flood kuralı tamamlandı. %d bulgu üretildi.", len(findings))
        return findings

    @staticmethod
    def _connection_key(
        packet: PacketInfo,
    ) -> tuple[tuple[str, int], tuple[str, int]]:
        """Bir TCP paketini, YÖNDEN BAĞIMSIZ bir bağlantı kimliğine indirger.

        Aynı bağlantının iki yönü (istemci->sunucu SYN ve sunucu->istemci
        SYN-ACK) aynı anahtarı üretmelidir; aksi halde bir SYN'in yanıtlanıp
        yanıtlanmadığı anlaşılamaz. İki uç nokta sıralanarak kanonik hale
        getirilir, böylece yön bilgisi anahtardan düşer.

        `or ""` / `or 0`: None uç nokta değerleri karşılaştırmada TypeError
        fırlatırdı. TCP paketlerinde portlar pratikte hep doludur; bu yalnızca
        bozuk/kısmi bir pakette kuralın çökmemesini garanti eder.
        """
        endpoint_a = (packet.src_ip or "", packet.src_port or 0)
        endpoint_b = (packet.dst_ip or "", packet.dst_port or 0)
        return (endpoint_a, endpoint_b) if endpoint_a <= endpoint_b else (endpoint_b, endpoint_a)

    @classmethod
    def _collect_syn_ack_times(
        cls, packets: list[PacketInfo]
    ) -> dict[tuple[tuple[str, int], tuple[str, int]], list[float]]:
        """Bağlantı anahtarı -> SYN-ACK zamanları (artan sırada) haritası üretir.

        Küme değil ZAMAN LİSTESİ tutulur, çünkü "bu bağlantı yanıtlandı mı"
        sorusu zamandan bağımsız sorulamaz: ephemeral portlar çekirdek
        tarafından geri dönüşüme sokulduğu için aynı 4'lü capture içinde
        birden çok kez, farklı sonuçlarla görülebilir (bkz.
        `config.FAILED_TCP_HANDSHAKE_TIMEOUT_SECONDS`).

        Yalnızca SYN-ACK "başarılı yanıt" sayılır. RST ile reddedilen bir
        bağlantı bilinçli olarak BAŞARISIZ kabul edilir: port taramasının
        tipik imzası tam olarak budur (SYN -> RST) ve analistin görmek
        isteyeceği şey de odur.
        """
        syn_ack_times: dict[tuple[tuple[str, int], tuple[str, int]], list[float]] = defaultdict(list)
        for packet in packets:
            flags = packet.tcp_flags or ""
            if packet.transport_protocol == "TCP" and "S" in flags and "A" in flags:
                syn_ack_times[cls._connection_key(packet)].append(packet.epoch_time)

        for times in syn_ack_times.values():
            times.sort()
        return syn_ack_times

    @staticmethod
    def _is_answered_within_timeout(
        syn_time: float, syn_ack_times: list[float], timeout: int
    ) -> bool:
        """SYN'den SONRA ve zaman aşımı içinde bir SYN-ACK var mı?

        `bisect_left` ile O(log n): bir 4'lü için yüzlerce SYN-ACK
        birikebileceğinden (uzun capture'larda port yeniden kullanımı) doğrusal
        arama, kuralın tamamını ikinci dereceden maliyete taşırdı.
        """
        index = bisect_left(syn_ack_times, syn_time)
        return index < len(syn_ack_times) and syn_ack_times[index] <= syn_time + timeout

    def _detect_failed_tcp_connections(self, packets: list[PacketInfo]) -> list[ThreatFinding]:
        """Yanıtlanmamış TCP bağlantı denemelerinin yoğunlaştığı pencereleri tespit eder.

        "Başarısız" tanımı: gönderilmiş bir SYN'e, `config.
        FAILED_TCP_HANDSHAKE_TIMEOUT_SECONDS` içinde karşılık gelen bir
        SYN-ACK ulaşmaması. RST ile reddedilenler de başarısız sayılır --
        SYN -> RST, port taramasının tipik imzasıdır.

        Sayılan birim PAKET DEĞİL BAĞLANTIDIR: yeniden gönderilen SYN'ler tek
        bir denemeye indirgenir (bkz. metot gövdesindeki açıklama).

        BİLİNEN KAPSAM SINIRI: hedefin YANIT VERDİĞİ hacimsel bir SYN flood bu
        kuralın kapsamına girmez -- her SYN yanıtlandığı için hiçbiri
        "başarısız" değildir. Bu senaryo `_detect_syn_flood` tarafından,
        kaynağa değil HEDEFE göre gruplanarak ayrıca ele alınır.

        Bir SYN ile ona ait SYN-ACK zıt yönlerde aktığı için eşleştirme,
        IP çifti kovalarından bağımsız, yön duyarsız bir bağlantı anahtarı
        üzerinden yapılır (bkz. `_connection_key`). Bu ayrımın atlanması
        kuralın en ciddi yanlış-pozitif kaynağıydı: SYN-ACK hiçbir zaman
        SYN'in kovasında olmadığı için her SYN yanıtsız sayılıyor ve aynı
        hedefe 60 saniyede 20+ bağlantı açan sıradan bir istemci (tarayıcı,
        yedekleme ajanı, API çağıran servis) MEDIUM bulgu üretiyordu.
        """
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

        # Yanıt zamanları, IP ÇİFTİ KOVALARINDAN BAĞIMSIZ olarak, tüm paketler
        # üzerinden tek bir geçişte toplanır.
        #
        # NEDEN BÖYLE OLMAK ZORUNDA: Bir SYN istemciden sunucuya, ona karşılık
        # gelen SYN-ACK ise sunucudan istemciye gider. Kovalar (src_ip, dst_ip)
        # ile anahtarlandığı için bu iki paket FARKLI kovalara düşer; SYN-ACK
        # aranırken yalnızca SYN'in kendi kovasına bakmak, orada hiçbir zaman
        # SYN-ACK bulunmaması demekti. Sonuç: her SYN "yanıtsız" sayılıyordu ve
        # kural, aynı hedefe 60 saniyede 20+ bağlantı açan HERHANGİ bir istemci
        # için (sıradan bir tarayıcı, yedekleme istemcisi, API çağrısı yapan bir
        # servis) MEDIUM bulgu üretiyordu. Doğrulandı: 25 paket alışverişi tam
        # ve başarılı el sıkışma "25 adet başarısız TCP bağlantı denemesi"
        # olarak raporlanıyordu.
        syn_ack_times = self._collect_syn_ack_times(packets)
        handshake_timeout = config.FAILED_TCP_HANDSHAKE_TIMEOUT_SECONDS

        for (src_ip, dst_ip), tcp_pkts in ip_pair_buckets.items():
            # Yalnızca saf SYN (el sıkışmanın ilk adımı) bir "deneme"dir;
            # SYN-ACK zaten yanıtın kendisidir.
            #
            # BAĞLANTI BAŞINA TEK KAYIT: TCP, yanıt alamadığı bir SYN'i aynı
            # 4'lü üzerinden defalarca yeniden gönderir (Linux varsayılanı
            # tcp_syn_retries=6 -> t=0,1,3,7,15,31,63 sn). Her retransmission
            # ayrı bir "deneme" sayılırsa TEK bir başarısız bağlantı 6-7 kez
            # sayılır: güvenlik duvarı tarafından sessizce düşürülen bir
            # servise 4 soket açan sıradan bir istemci, 24 paketle 20'lik eşiği
            # aşıp MEDIUM bulgu üretirdi. Bulgunun "24 adet başarısız bağlantı
            # denemesi" iddiası da gerçekle örtüşmezdi -- gerçek sayı 4'tü.
            # Bağlantı başına EN ERKEN SYN temsilci alınır.
            earliest_syn_per_connection: dict[
                tuple[tuple[str, int], tuple[str, int]], PacketInfo
            ] = {}
            for pkt in tcp_pkts:
                if pkt.tcp_flags != "S":
                    continue
                key = self._connection_key(pkt)
                if self._is_answered_within_timeout(
                    pkt.epoch_time, syn_ack_times.get(key, []), handshake_timeout
                ):
                    continue
                existing = earliest_syn_per_connection.get(key)
                if existing is None or pkt.epoch_time < existing.epoch_time:
                    earliest_syn_per_connection[key] = pkt

            failed_syn_pkts = list(earliest_syn_per_connection.values())

            if len(failed_syn_pkts) < threshold:
                continue

            sorted_failed = sorted(failed_syn_pkts, key=lambda p: p.epoch_time)

            for left, right in self._slide_count_windows(sorted_failed, time_window, threshold):
                window_pkts = sorted_failed[left:right]
                count = len(window_pkts)
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
                base_domain = self._compute_base_domain(pkt.dns_query_name)
                domain_buckets[(pkt.src_ip, base_domain)].append(pkt)

        for (src_ip, base_domain), dns_pkts in domain_buckets.items():
            if len(dns_pkts) < query_threshold:
                continue

            sorted_pkts = sorted(dns_pkts, key=lambda p: p.epoch_time)

            for left, right in self._slide_count_windows(sorted_pkts, time_window, query_threshold):
                window_pkts = sorted_pkts[left:right]
                count = len(window_pkts)
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

        logger.info("DNS Tunneling kuralı tamamlandı. %d bulgu üretildi.", len(findings))
        return findings

    def _detect_long_domains(
        self,
        packets: list[PacketInfo],
        query_domains: dict[str, list[PacketInfo]] | None = None,
    ) -> list[ThreatFinding]:
        """Aşırı uzun alan adı (Long Domain) sorgularını tespit eder.

        `query_domains` verilirse (bkz. `detect()`), alan adı haritası yeniden
        kurulmaz; DGA kuralıyla paylaşılan tek bir harita kullanılır.
        Verilmezse kural tek başına da çalışabilir.
        """
        logger.info("Long Domain kuralı çalıştırılıyor...")
        findings: list[ThreatFinding] = []

        domains_map = (
            query_domains
            if query_domains is not None
            else self._collect_unique_query_domains(packets)
        )
        long_domains_evidence: list[dict[str, float | str | int]] = []

        for domain, domain_pkts in domains_map.items():
            if len(domain) > config.LONG_DOMAIN_LENGTH:
                first_pkt = self._earliest_packet(domain_pkts)
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

    def _detect_dga_domains(
        self,
        packets: list[PacketInfo],
        query_domains: dict[str, list[PacketInfo]] | None = None,
    ) -> list[ThreatFinding]:
        """Yüksek entropili DGA (Domain Generation Algorithm) alan adlarını tespit eder.

        `query_domains` için bkz. `_detect_long_domains` — iki kural aynı
        alan adı haritasını paylaşır.
        """
        logger.info("DGA Detection kuralı çalıştırılıyor...")
        findings: list[ThreatFinding] = []

        domains_map = (
            query_domains
            if query_domains is not None
            else self._collect_unique_query_domains(packets)
        )
        dga_evidence: list[dict[str, float | str]] = []

        for domain, domain_pkts in domains_map.items():
            parts = domain.split(".")
            label = parts[0] if parts else domain

            if len(label) >= config.DGA_MIN_LABEL_LENGTH:
                entropy = self._shannon_entropy(label)
                if entropy >= config.DGA_ENTROPY_THRESHOLD:
                    first_pkt = self._earliest_packet(domain_pkts)
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
        """Zaman penceresi içinde aşırı dışa veri aktarımı (Data Exfiltration) durumlarını tespit eder.

        NOT: Önceki sürüm zaman penceresi kullanmıyordu; tüm capture boyunca
        biriken toplam byte doğrudan eşikle karşılaştırılıyordu. Bu, saatlerce
        süren bir capture'da tamamen sıradan bir indirme/video akışının bile
        (örn. birkaç saatte 60 MB'lık bir işletim sistemi güncellemesi) 10
        saniyede aynı hacmi bir C2'ye sızdıran bir saldırıyla AYNI CRITICAL
        skoru üretmesine yol açıyordu — hacim hiçbir zaman hıza/zamana göre
        değerlendirilmiyordu. Diğer kayan-pencere kurallarıyla (ICMP flood,
        failed-TCP, DNS tunneling) aynı `_slide_count_windows` mekanizması
        `weight_fn=lambda p: p.length` ile yeniden kullanılarak artık hacim,
        sabit bir `config.EXFILTRATION_TIME_WINDOW_SECONDS` penceresi
        İÇİNDE ölçülür; bu "kısa sürede yüksek hacim" olan gerçek sızdırma
        davranışını "yavaş ve sürekli" sıradan trafikten ayırır.
        """
        logger.info("Exfiltration kuralı çalıştırılıyor...")
        findings: list[ThreatFinding] = []

        time_window = config.EXFILTRATION_TIME_WINDOW_SECONDS
        threshold = config.EXFILTRATION_THRESHOLD

        # (src_ip, dst_ip) -> list[PacketInfo] (yalnızca egress trafiği)
        pair_buckets: dict[tuple[str, str], list[PacketInfo]] = defaultdict(list)

        for pkt in packets:
            if (
                pkt.src_ip
                and pkt.dst_ip
                and pkt.epoch_time
                and pkt.epoch_time > 0
                and self._is_egress_traffic(pkt.src_ip, pkt.dst_ip)
            ):
                pair_buckets[(pkt.src_ip, pkt.dst_ip)].append(pkt)

        for (src_ip, dst_ip), pair_packets in pair_buckets.items():
            # Hızlı ön-eleme: bir pencerenin byte toplamı, tüm çiftin
            # toplamını asla aşamaz; çiftin toplamı eşiğin altındaysa hiçbir
            # pencere de eşiği geçemez (ICMP flood/failed-TCP kurallarındaki
            # "len(...) < threshold: continue" ön-elemesiyle aynı desen).
            if sum(p.length for p in pair_packets) < threshold:
                continue

            sorted_pkts = sorted(pair_packets, key=lambda p: p.epoch_time)

            for left, right in self._slide_count_windows(
                sorted_pkts, time_window, threshold, weight_fn=lambda p: p.length
            ):
                window_pkts = sorted_pkts[left:right]
                total_bytes = sum(p.length for p in window_pkts)
                first_seen = window_pkts[0].epoch_time
                last_seen = window_pkts[-1].epoch_time
                mb_size = total_bytes / (1024 * 1024)

                finding = ThreatFinding(
                    rule_id="SEC-EXFIL-001",
                    title="Yüksek Hacimli Veri Sızdırma (Data Exfiltration) Tespiti",
                    severity=ThreatSeverity.CRITICAL,
                    description=(
                        f"{src_ip} iç IP adresinden {dst_ip} dış IP adresine {time_window} "
                        f"saniye içinde {mb_size:.2f} MB boyutunda şüpheli veri aktarımı tespiti yapıldı."
                    ),
                    evidence={
                        "total_bytes": total_bytes,
                        "total_megabytes": round(mb_size, 2),
                        "threshold_bytes": threshold,
                        "time_window_seconds": time_window,
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
