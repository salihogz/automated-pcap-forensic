"""
Automated PCAP Forensic Analysis Tool - CLI Entry Point
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import logging
import sys
from pathlib import Path
from time import perf_counter

from dotenv import load_dotenv

load_dotenv()
import config
from modules.parser import PCAPParser
from modules.reporter import Reporter
from modules.statistics import build_general_statistics
from modules.threat_detector import ThreatDetector
from modules.threat_intel import (
    NormalizedIOCResult,
    ThreatIntelService,
    build_default_providers,
    build_default_session,
)

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False) -> None:
    """Merkezi loglama yapılandırmasını başlatır."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(config.LOGS_DIR / config.DEFAULT_LOG_NAME, encoding="utf-8"),
        ],
        force=True,
    )


def _is_public_ip(ip_str: str) -> bool:
    """IP, dış Threat Intel sağlayıcılarına sorgulamaya değer (genel/routable) mi?

    Private (RFC1918), loopback, link-local, multicast ve diğer reserved
    aralıklar dış TI servisleri için anlamlı bir sonuç üretmez: bazı
    sağlayıcılar bunları HTTP 400 ile reddeder (bkz. OTX), bazıları ise
    "veri yok" durumunu sessizce "temiz" ile karıştırılabilecek bir sonuca
    çevirir. İkisi de raporu ya gereksiz hata satırlarıyla ya da yanıltıcı
    "BAŞARILI/CLEAN" satırlarıyla kirletir. Bu yüzden private IP'ler dış
    sorgudan tamamen hariç tutulur; iç ağ analizi zaten Threat Detector
    kurallarının (port scan vb.) sorumluluğundadır.
    """
    try:
        return ipaddress.ip_address(ip_str).is_global
    except ValueError:
        return False


def print_banner() -> None:
    banner = """
    ===============================================================
     Automated PCAP Forensic Analysis Tool (DFIR)
     Sürüm: 1.1.0-refactored | Adli Bilişim Paket Analiz Aracı
    ===============================================================
    """
    print(banner)


def parse_arguments() -> argparse.Namespace:
    arg_parser = argparse.ArgumentParser(description="PCAP/PCAPNG adli analiz aracı.")
    arg_parser.add_argument("-f", "--file", type=Path, help="Analiz edilecek PCAP dosya yolu")
    arg_parser.add_argument("-v", "--verbose", action="store_true", help="Debug seviyesinde loglama")
    return arg_parser.parse_args()


def resolve_target_path(args: argparse.Namespace) -> Path | None:
    """Hedef pcap dosyasını -f parametresinden ya da samples/ dizininden (alt klasörler dahil) belirler."""
    if args.file:
        if not args.file.exists():
            logger.error("Belirtilen dosya bulunamadı: %s", args.file)
            return None
        return args.file

    # rglob kullanılıyor çünkü örnek dosyalar samples/clean/ ve
    # samples/malicious/ alt klasörlerinde tutuluyor.
    sample_files = sorted(
        f for ext in config.SUPPORTED_EXTENSIONS for f in config.SAMPLES_DIR.rglob(f"*{ext}")
    )
    if not sample_files:
        logger.error("Lütfen bir PCAP dosyası belirtin!")
        return None

    target_path = sample_files[0]
    logger.info("Dosya parametresi verilmedi. Örnek dosya seçildi: %s", target_path.name)
    return target_path


def main() -> int:
    args = parse_arguments()
    setup_logging(args.verbose)
    print_banner()

    target_path = resolve_target_path(args)
    if target_path is None:
        return 1

    try:
        logger.info("Hedef dosya: %s", target_path)
        start_time = perf_counter()

        # 1. Parsing
        pcap_parser = PCAPParser(target_path)
        packets = pcap_parser.parse()

        # 2. General Statistics Generation
        stats = build_general_statistics(packets)

        # 3. Threat Detection Engine
        detector = ThreatDetector(stats)
        findings = detector.detect(packets)

        # 4. Threat Intelligence
        unique_ips = {
            ip
            for packet in packets
            for ip in (packet.src_ip, packet.dst_ip)
            if ip is not None
        }

        public_ips = sorted(ip for ip in unique_ips if _is_public_ip(ip))
        skipped_ip_count = len(unique_ips) - len(public_ips)
        if skipped_ip_count:
            logger.info(
                "Threat Intelligence: %d private/rezerve IP sorgu dışında bırakıldı "
                "(dış TI sağlayıcıları için anlamlı değil).",
                skipped_ip_count,
            )

        session = build_default_session()
        providers = build_default_providers(session)
        threat_intel = ThreatIntelService(providers)

        threat_intel_results: dict[str, list[NormalizedIOCResult]] = {}

        # Threat Intelligence sorgularını ThreadPoolExecutor ile paralel çalıştırma
        if public_ips:
            max_workers = min(10, len(public_ips))  # İsteğe bağlı olarak worker sayısını sınırlayabilirsiniz
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                results = executor.map(threat_intel.enrich, public_ips)
                for ip, result in zip(public_ips, results):
                    threat_intel_results[ip] = result

        session.close()

        duration = perf_counter() - start_time

        logger.info(
            "Threat Intelligence sorgulanan benzersiz IP sayısı: %d",
            len(threat_intel_results),
        )

        reporter = Reporter()

        if args.verbose:
            print("\n--- THREAT INTELLIGENCE ---")

            for ip, results in threat_intel_results.items():
                print(f"\nIP: {ip}")

                for result in results:
                    print(
                        f"  {result.source:<18} "
                        f"Malicious={result.is_malicious} "
                        f"Score={result.raw_score}"
                    )

        # 5. HTML Report Generation
        report_path = reporter.generate(
            statistics=stats,
            findings=findings,
            threat_intel=threat_intel_results,
            source_file=target_path,
            analysis_duration=duration,
        )
        logger.info("HTML raporu oluşturuldu: %s", report_path)

        logger.info(
            "İşlem %.2f saniyede tamamlandı. Ayrıştırılan paket sayısı: %d",
            duration,
            len(packets),
        )
        logger.info(
            "Statistics oluşturuldu. Threat Findings: %d",
            len(findings),
        )

        # 6. Console Outputs (Verbose modda hızlı debug çıktıları)
        if packets and args.verbose:
            print("\n--- İLK 3 PAKET (Dataclass Örneği) ---")
            for pkt in packets[:3]:
                print(pkt)

        if findings and args.verbose:
            print("\n--- THREAT FINDINGS ---")
            for finding in findings:
                print(finding)

        return 0

    except (FileNotFoundError, ValueError, RuntimeError) as e:
        logger.error("Analiz başarısız oldu: %s", e)
        return 1
    except Exception:
        logger.exception("Beklenmeyen bir hata oluştu.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())