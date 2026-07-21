"""
Automated PCAP Forensic Analysis Tool - CLI Entry Point
"""
import sys
import logging
import argparse
from pathlib import Path
from time import perf_counter
from typing import Optional

import config
from modules.parser import PCAPParser

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
        force=True
    )


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


def resolve_target_path(args: argparse.Namespace) -> Optional[Path]:
    """Hedef pcap dosyasını -f parametresinden ya da samples/ dizininden belirler."""
    if args.file:
        if not args.file.exists():
            logger.error(f"Belirtilen dosya bulunamadı: {args.file}")
            return None
        return args.file

    sample_files = sorted(
        f for ext in config.SUPPORTED_EXTENSIONS for f in config.SAMPLES_DIR.glob(f"*{ext}")
    )
    if not sample_files:
        logger.error("Lütfen bir PCAP dosyası belirtin!")
        return None

    target_path = sample_files[0]
    logger.info(f"Dosya parametresi verilmedi. Örnek dosya seçildi: {target_path.name}")
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
        
        pcap_parser = PCAPParser(target_path)
        packets = pcap_parser.parse()
        
        duration = perf_counter() - start_time
        logger.info(f"İşlem {duration:.2f} saniyede tamamlandı. Ayrıştırılan paket sayısı: {len(packets)}")

        if packets and args.verbose:
            print("\n--- İLK 3 PAKET (Dataclass Örneği) ---")
            for pkt in packets[:3]:
                print(pkt)
        return 0

    except (FileNotFoundError, ValueError, RuntimeError) as e:
        logger.error(f"Analiz başarısız oldu: {e}")
        return 1
    except Exception as e:
        logger.exception(f"Beklenmeyen bir hata oluştu: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())