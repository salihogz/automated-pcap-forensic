"""Depoya girecek sentetik örnek capture'ı üretir.

Neden sentetik: gerçek bir capture, yakalandığı ağın iç IP'lerini ve gezilen
siteleri içerir; herkese açık bir depoya konulamaz. Buradaki trafik tamamen
uydurmadır ve yalnızca RFC 5737 (TEST-NET) ile RFC 1918 (özel ağ)
aralıklarındaki adresleri kullanır -- bu adresler tanım gereği gerçek bir
hosta ait olamaz.

Üretilen dosya, tespit motorunun kurallarını bilinçli olarak tetikler; böylece
`python main.py` çalıştıran birisi boş bir rapor yerine dolu bir rapor görür.
Zaman damgaları sabit bir başlangıçtan üretilir, dolayısıyla script her
çalıştığında bit düzeyinde aynı dosya oluşur (tekrarlanabilirlik).

Kullanım:
    python scripts/generate_sample_capture.py
"""

from __future__ import annotations

import random
import string
from pathlib import Path

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Packet
from scapy.utils import PcapNgWriter

# --------------------------------------------------------------------
# Sabitler
# --------------------------------------------------------------------

# Sabit başlangıç zamanı -> deterministik çıktı. 2026-03-01 09:00:00 UTC.
BASE_TIME = 1772355600.0

# Tekrarlanabilir "rastgelelik" (DGA/tünel etiketleri için).
RNG = random.Random(20260301)

# RFC 1918 - iç ağ
WORKSTATION = "10.0.0.15"
DNS_SERVER = "10.0.0.1"
COMPROMISED_HOST = "10.0.0.66"  # taramayı yapan iç host
INTERNAL_SERVER = "10.0.0.20"  # taramanın hedefi

# RFC 5737 - dokümantasyon amaçlı, yönlendirilemez dış adresler
EXT_WEB_TLS = "192.0.2.10"
EXT_WEB_HTTP = "198.51.100.25"
EXT_NTP = "203.0.113.7"

MAC_A = "02:00:00:00:00:01"
MAC_B = "02:00:00:00:00:02"

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "samples" / "malicious" / "demo_capture.pcapng"


def _frame(packet: Packet, timestamp: float) -> Packet:
    """Paketi Ethernet çerçevesine sarar ve zaman damgasını atar."""
    framed = Ether(src=MAC_A, dst=MAC_B) / packet
    framed.time = timestamp
    return framed


def _random_label(length: int) -> str:
    """DGA/tünel etiketlerini taklit eden yüksek entropili etiket üretir."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(RNG.choice(alphabet) for _ in range(length))


# --------------------------------------------------------------------
# Trafik üreticileri
# --------------------------------------------------------------------


def benign_dns(packets: list[Packet], start: float) -> None:
    """Normal DNS sorgu/yanıt trafiği.

    Yanıtlar bilinçli olarak her seferinde FARKLI bir ephemeral porta gider
    (53 -> 41xxx). Bu, `_is_probable_response_packet` filtresi olmasaydı
    "onlarca farklı porta erişim" gibi okunup yanlış bir port taraması
    bulgusu üretecek olan desendir; örnek capture'ın bu regresyonu da
    kapsaması isteniyor.
    """
    domains = ["example.com", "example.net", "example.org", "test.example"]
    for i in range(40):
        client_port = 41000 + i * 7
        ts = start + i * 0.8
        query = IP(src=WORKSTATION, dst=DNS_SERVER) / UDP(sport=client_port, dport=53) / DNS(
            rd=1, qd=DNSQR(qname=domains[i % len(domains)], qtype="A")
        )
        packets.append(_frame(query, ts))

        answer = IP(src=DNS_SERVER, dst=WORKSTATION) / UDP(sport=53, dport=client_port) / DNS(
            id=1, qr=1, qd=DNSQR(qname=domains[i % len(domains)], qtype="A")
        )
        packets.append(_frame(answer, ts + 0.02))


def benign_web(packets: list[Packet], start: float) -> None:
    """Tamamlanmış TCP el sıkışmaları + veri aktarımı (HTTPS ve HTTP)."""
    for idx, (server, port) in enumerate([(EXT_WEB_TLS, 443), (EXT_WEB_HTTP, 80)]):
        client_port = 52000 + idx * 100
        ts = start + idx * 5

        syn = IP(src=WORKSTATION, dst=server) / TCP(sport=client_port, dport=port, flags="S")
        syn_ack = IP(src=server, dst=WORKSTATION) / TCP(sport=port, dport=client_port, flags="SA")
        ack = IP(src=WORKSTATION, dst=server) / TCP(sport=client_port, dport=port, flags="A")
        packets.append(_frame(syn, ts))
        packets.append(_frame(syn_ack, ts + 0.03))
        packets.append(_frame(ack, ts + 0.04))

        for n in range(12):
            payload = bytes(RNG.getrandbits(8) for _ in range(800))
            packets.append(
                _frame(
                    IP(src=WORKSTATION, dst=server) / TCP(sport=client_port, dport=port, flags="PA") / payload,
                    ts + 0.1 + n * 0.2,
                )
            )
            packets.append(
                _frame(
                    IP(src=server, dst=WORKSTATION) / TCP(sport=port, dport=client_port, flags="PA") / payload,
                    ts + 0.15 + n * 0.2,
                )
            )


def benign_ntp(packets: list[Packet], start: float) -> None:
    """NTP istek/yanıt -- yanıt yine servis portundan ephemeral porta gider."""
    for i in range(6):
        client_port = 45000 + i * 3
        ts = start + i * 10
        request = IP(src=WORKSTATION, dst=EXT_NTP) / UDP(sport=client_port, dport=123) / (b"\x1b" + b"\x00" * 47)
        reply = IP(src=EXT_NTP, dst=WORKSTATION) / UDP(sport=123, dport=client_port) / (b"\x1c" + b"\x00" * 47)
        packets.append(_frame(request, ts))
        packets.append(_frame(reply, ts + 0.05))


def port_and_syn_scan(packets: list[Packet], start: float) -> None:
    """SEC-PORT-SCAN-001, SEC-SYN-SCAN-001 ve SEC-FAILED-TCP-001.

    Ephemeral kaynak porttan çok sayıda servis portuna SYN gönderilir ve
    hiçbirine SYN-ACK dönmez: yarım açık (half-open) tarama deseni.
    """
    target_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
        993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
    ]
    for i, port in enumerate(target_ports):
        ts = start + i * 0.4
        packets.append(
            _frame(
                IP(src=COMPROMISED_HOST, dst=INTERNAL_SERVER) / TCP(sport=49152 + i, dport=port, flags="S"),
                ts,
            )
        )


def icmp_flood(packets: list[Packet], start: float) -> None:
    """SEC-ICMP-FLOOD-001: 10 saniyelik pencerede 100'den fazla ICMP paketi."""
    for i in range(150):
        packets.append(
            _frame(
                IP(src=COMPROMISED_HOST, dst=INTERNAL_SERVER) / ICMP(type=8, seq=i) / (b"\x00" * 56),
                start + i * 0.05,
            )
        )


def dns_tunneling(packets: list[Packet], start: float) -> None:
    """SEC-DNS-TUNNEL-001, SEC-LONG-DOMAIN-001 ve SEC-DGA-001.

    Tek bir taban alan adına, veri taşıyormuş gibi görünen uzun ve yüksek
    entropili alt alan adlarıyla çok sayıda TXT sorgusu.
    """
    for i in range(45):
        label_a = _random_label(28)
        label_b = _random_label(24)
        qname = f"{label_a}.{label_b}.tunnel.example.com"
        packets.append(
            _frame(
                IP(src=COMPROMISED_HOST, dst=DNS_SERVER)
                / UDP(sport=48000 + i, dport=53)
                / DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT")),
                start + i * 1.1,
            )
        )


def main() -> None:
    packets: list[Packet] = []

    benign_dns(packets, BASE_TIME)
    benign_web(packets, BASE_TIME + 5)
    benign_ntp(packets, BASE_TIME + 10)
    port_and_syn_scan(packets, BASE_TIME + 120)
    icmp_flood(packets, BASE_TIME + 180)
    dns_tunneling(packets, BASE_TIME + 240)

    packets.sort(key=lambda pkt: pkt.time)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with PcapNgWriter(str(OUTPUT_PATH)) as writer:
        for packet in packets:
            writer.write(packet)

    size_kb = OUTPUT_PATH.stat().st_size / 1024
    print(f"{len(packets)} paket yazıldı -> {OUTPUT_PATH} ({size_kb:.1f} KB)")


if __name__ == "__main__":
    main()
