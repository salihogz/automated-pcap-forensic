"""
Automated PCAP Forensic Analysis Tool - CLI Entry Point
"""

import argparse
import ipaddress
import logging
import sys
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from time import perf_counter

from dotenv import load_dotenv

load_dotenv()
import config
from modules.exporters import EXPORTERS, ExportError, ExportPayload
from modules.output_paths import resolve_output_dir
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

# `--format` seçeneğinin kabul ettiği değerler. "html" listenin başındadır ve
# varsayılandır: araç bugüne kadar HTML raporu üretiyordu, bayrak verilmeyen
# çağrılar aynı şekilde davranmaya devam etmelidir (geriye uyumluluk).
HTML_FORMAT = "html"
ALL_FORMATS_KEYWORD = "all"
SUPPORTED_FORMATS: tuple[str, ...] = (HTML_FORMAT, *EXPORTERS)

# Paralel Threat Intelligence sorgusu için üst sınır. Sağlayıcıların ücretsiz
# katmanları oran sınırlıdır (ör. VirusTotal: dakikada 4 istek); worker sayısını
# artırmak sorguyu hızlandırmaz, yalnızca 429 yanıtlarını çoğaltır.
MAX_THREAT_INTEL_WORKERS = 10


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
    # Scapy'nin SSLv2 katmanındaki "Unknown cipher suite ..." gürültüsünü sustur.
    # Bu bir hata değil, pcap içindeki eski/rastgele cipher-suite ID'lerinden kaynaklanıyor.
    logging.getLogger("scapy").setLevel(logging.ERROR)
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


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
        address = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    # `is_global` multicast adresleri için True döner (224.0.0.251 mDNS,
    # 239.255.255.250 SSDP, 224.0.0.252 LLMNR, ff02::fb ...). Bu adresler
    # neredeyse her yerel ağ capture'ında bulunduğu için, ayrıca elenmezlerse
    # her analizde onlarca anlamsız TI sorgusu yapılır -- VirusTotal'ın ücretsiz
    # kotası günde 500 istek olduğundan bu, gerçek IP'ler için kalan kotayı
    # tüketir. Multicast bir hedef host değil, bir dağıtım grubudur; dış TI
    # sağlayıcılarında karşılığı yoktur.
    return address.is_global and not address.is_multicast


def print_banner() -> None:
    banner = f"""
    ===============================================================
     Automated PCAP Forensic Analysis Tool (DFIR)
     Sürüm: {config.TOOL_VERSION} | Adli Bilişim Paket Analiz Aracı
    ===============================================================
    """
    print(banner)


def parse_arguments() -> argparse.Namespace:
    arg_parser = argparse.ArgumentParser(description="PCAP/PCAPNG adli analiz aracı.")
    arg_parser.add_argument("-f", "--file", type=Path, help="Analiz edilecek PCAP dosya yolu")
    arg_parser.add_argument("-v", "--verbose", action="store_true", help="Debug seviyesinde loglama")
    arg_parser.add_argument(
        "--format",
        nargs="+",
        choices=[*SUPPORTED_FORMATS, ALL_FORMATS_KEYWORD],
        default=[HTML_FORMAT],
        metavar="BİÇİM",
        help=(
            "Üretilecek çıktı biçimleri (birden fazla verilebilir): "
            f"{', '.join(SUPPORTED_FORMATS)} veya '{ALL_FORMATS_KEYWORD}'. Varsayılan: {HTML_FORMAT}"
        ),
    )
    return arg_parser.parse_args()


def resolve_export_formats(requested: Sequence[str]) -> list[str]:
    """`--format` değerlerini, tekrarları ayıklanmış kanonik sıraya çevirir.

    Sıra `SUPPORTED_FORMATS`'tan gelir, kullanıcının yazdığı sıradan değil:
    HTML raporunun önce üretilmesi, uzun süren PDF/CSV adımlarından biri
    beklenmedik bir şekilde başarısız olsa bile analistin elinde en kapsamlı
    çıktının bulunmasını sağlar.
    """
    if ALL_FORMATS_KEYWORD in requested:
        return list(SUPPORTED_FORMATS)
    return [fmt for fmt in SUPPORTED_FORMATS if fmt in set(requested)]


def run_exporters(payload: ExportPayload, formats: Sequence[str]) -> tuple[list[Path], list[str]]:
    """İstenen export biçimlerini çalıştırır; (yazılan dosyalar, başarısız biçimler) döndürür.

    Bir biçimin başarısız olması diğerlerini DURDURMAZ: PDF üretimi (ör.
    reportlab kurulu değilse) patladığında, aynı analizden üretilen JSON ve
    CSV çıktılarının da kaybedilmesi için hiçbir sebep yoktur. Başarısızlıklar
    yine de sessizce yutulmaz -- çağırana bildirilir ve çıkış kodunu etkiler.
    """
    output_dir = resolve_output_dir(payload.source_file)
    written: list[Path] = []
    failed: list[str] = []

    for format_name in formats:
        if format_name == HTML_FORMAT:
            continue  # HTML, Reporter tarafından ayrıca üretiliyor.
        try:
            written.extend(EXPORTERS[format_name]().export(payload, output_dir))
        except ExportError as exc:
            logger.error("%s export'u başarısız oldu: %s", format_name.upper(), exc)
            failed.append(format_name)

    return written, failed


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

        threat_intel_results: dict[str, list[NormalizedIOCResult]] = {}

        # Session bir context manager içinde açılır: bir sağlayıcı sorgusu
        # beklenmedik bir hata fırlatsa dahi bağlantı havuzu kapatılır.
        # (Önceki sürümde `session.close()` düz bir satırdı ve bu blokta
        # oluşan herhangi bir istisnada hiç çalışmıyor, soketler process
        # sonuna kadar açık kalıyordu.)
        with build_default_session() as session:
            providers = build_default_providers(session)
            threat_intel = ThreatIntelService(providers)

            # Threat Intelligence sorgularını ThreadPoolExecutor ile paralel çalıştırma
            if public_ips:
                max_workers = min(MAX_THREAT_INTEL_WORKERS, len(public_ips))
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    enrich_results = executor.map(threat_intel.enrich, public_ips)
                    # strict=True: executor.map girdiyle birebir aynı sayıda sonuç
                    # üretmeli; üretmiyorsa IP'ler sonuçlarla kayar ve yanlış IP'ye
                    # yanlış TI verisi eşlenir. Sessizce kısalmaktansa hata versin.
                    for ip, ip_results in zip(public_ips, enrich_results, strict=True):
                        threat_intel_results[ip] = ip_results

        duration = perf_counter() - start_time

        logger.info(
            "Threat Intelligence sorgulanan benzersiz IP sayısı: %d",
            len(threat_intel_results),
        )

        reporter = Reporter()

        if args.verbose:
            print("\n--- THREAT INTELLIGENCE ---")

            for ip, ip_results in threat_intel_results.items():
                print(f"\nIP: {ip}")

                for result in ip_results:
                    print(
                        f"  {result.source:<18} "
                        f"Malicious={result.is_malicious} "
                        f"Score={result.raw_score}"
                    )

        # 5. Report / Export Generation
        export_formats = resolve_export_formats(args.format)

        # Payload biçimlerden ÖNCE kurulur: SHA-256 özetini bir kez hesaplar ve
        # aynı değeri hem HTML raporuna hem de export'lara verir. Aksi halde
        # GB boyutundaki bir delil dosyası her çıktı için baştan sona okunurdu.
        payload = ExportPayload.build(
            statistics=stats,
            findings=findings,
            threat_intel=threat_intel_results,
            source_file=target_path,
            analysis_duration=duration,
        )

        if HTML_FORMAT in export_formats:
            report_path = reporter.generate(
                statistics=stats,
                findings=findings,
                threat_intel=threat_intel_results,
                source_file=target_path,
                analysis_duration=duration,
                sha256=payload.sha256,
            )
            logger.info("HTML raporu oluşturuldu: %s", report_path)

        exported_paths, failed_formats = run_exporters(payload, export_formats)
        for exported_path in exported_paths:
            logger.info("Export oluşturuldu: %s", exported_path)

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

        # Kısmi başarı sessizce "başarılı" sayılmaz: analistin ya da bir
        # betiğin, istediği çıktılardan birinin üretilmediğini çıkış kodundan
        # anlayabilmesi gerekir. Üretilebilen çıktılar yine de yerinde kalır.
        if failed_formats:
            logger.error(
                "Şu export biçimleri üretilemedi: %s. Diğer çıktılar oluşturuldu.",
                ", ".join(failed_formats),
            )
            return 1

        return 0

    except (FileNotFoundError, ValueError, RuntimeError) as e:
        logger.error("Analiz başarısız oldu: %s", e)
        return 1
    except Exception:
        logger.exception("Beklenmeyen bir hata oluştu.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
