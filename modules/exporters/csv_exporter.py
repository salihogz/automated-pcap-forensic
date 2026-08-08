# modules/exporters/csv_exporter.py
"""
Automated PCAP Forensic Analysis Tool - CSV export.

NEDEN ÜÇ DOSYA: CSV tek bir düz tablodur; farklı şekilli üç veri kümesini
(bulgular, TI sonuçları, istatistikler) tek dosyaya sıkıştırmanın tek yolu
"bölüm başlıkları" koyup dosyayı yarı yapılandırılmış hale getirmektir --
ki bu, dosyayı hem CSV ayrıştırıcıları hem de Excel için bozar. Bu yüzden
her tablo kendi dosyasına, TEK ve TUTARLI bir şema ile yazılır:

    <capture>_findings.csv       bulgu başına bir satır
    <capture>_threat_intel.csv   (IP x sağlayıcı) başına bir satır
    <capture>_statistics.csv     metrik başına bir satır (uzun/tidy biçim)

İstatistikler "uzun biçimde" (category, key, value) yazılır çünkü içerdiği
alanların şekli birbirinden farklıdır: skaler toplamlar, protokol dağılımı,
Top-N listeleri ve zaman çizelgesi. Geniş biçimde her biri ayrı bir sütun
grubu isterdi; uzun biçim hepsini tek şemayla taşır ve Excel'de pivot
tablosuna doğrudan girdi olur.

Bulgular burada da (JSON'da olduğu gibi) HAM yazılır -- rapor görünümündeki
gruplama uygulanmaz. CSV'nin varlık sebebi satır satır süzme/pivotlamadır;
gruplanmış veri bunu imkânsız kılar.
"""
import csv
import json
import logging
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar, Final

from modules.exporters.base import Exporter, ExportError, ExportPayload
from modules.exporters.json_exporter import _json_default
from modules.models import GeneralStatistics, ThreatFinding
from modules.reporter import _prepare_threat_intel_for_template

logger = logging.getLogger(__name__)

# Excel, BOM'suz bir UTF-8 CSV'yi sistemin eski ANSI kod sayfasıyla açar ve
# Türkçe karakterleri bozar ("Şüpheli" -> "Ã…Å¸Ã¼pheli"). BOM'lu UTF-8
# (utf-8-sig) hem Excel'de hem de standart CSV ayrıştırıcılarında doğru
# okunur; adli çıktının en yaygın tüketicisi Excel olduğu için bu seçildi.
_CSV_ENCODING: Final[str] = "utf-8-sig"

# Üç durumlu `is_malicious` alanının CSV karşılıkları. None için boş hücre
# BİLİNÇLİ OLARAK kullanılmaz: boş hücre "veri yok" ile "false" arasında
# ayrım yapmayan bir okuyucuda sessizce "temiz" diye yorumlanabilir --
# projenin en çok önem verdiği hata sınıfı tam olarak budur.
_TRISTATE_LABELS: Final[dict[bool | None, str]] = {
    True: "true",
    False: "false",
    None: "unknown",
}

_FINDINGS_HEADER: Final[tuple[str, ...]] = (
    "rule_id",
    "severity",
    "title",
    "source",
    "destination",
    "timestamp_epoch",
    "timestamp_iso",
    "description",
    "evidence_json",
)

_THREAT_INTEL_HEADER: Final[tuple[str, ...]] = (
    "ip",
    "consensus_label",
    "consensus_detail",
    "total_providers",
    "answered_providers",
    "malicious_providers",
    "provider",
    "is_malicious",
    "raw_score",
    "confidence",
    "categories",
    "last_seen",
    "queried_at",
    "error_code",
    "error_message",
)

_STATISTICS_HEADER: Final[tuple[str, ...]] = ("category", "key", "value")


def _epoch_to_iso(epoch: float | None) -> str:
    """Epoch zamanı, saat dilimi ofseti taşıyan ISO 8601 metnine çevirir.

    ``None`` ve parser'ın bozuk zaman damgası sentinel'i (``0.0``) boş hücreye
    çevrilir: 1970-01-01 yazmak, capture'da gerçekten o tarihte bir olay varmış
    izlenimi verir (bkz. statistics.py'deki aynı gerekçe).
    """
    if not epoch:
        return ""
    try:
        return datetime.fromtimestamp(epoch).astimezone().isoformat()
    except (OverflowError, OSError, ValueError):
        logger.warning("CSV: geçersiz zaman damgası biçimlendirilemedi: %r", epoch)
        return ""


def _evidence_to_json(evidence: dict[str, Any]) -> str:
    """Kanıt sözlüğünü tek hücreye sığan kompakt JSON metnine çevirir.

    Ham ``str(dict)`` KULLANILMAZ: Python repr'ı tek tırnak kullanır, ``None``
    /``True`` yazar ve hiçbir standart ayrıştırıcı tarafından okunamaz. JSON,
    hücreyi hem insan tarafından okunur hem de programatik olarak
    ayrıştırılabilir bırakır.
    """
    try:
        return json.dumps(evidence, ensure_ascii=False, sort_keys=True, default=_json_default)
    except (TypeError, ValueError) as exc:
        logger.warning("CSV: kanıt alanı JSON'a çevrilemedi (%s); metin olarak yazılıyor.", exc)
        return json.dumps({"serialization_error": str(exc)}, ensure_ascii=False)


class CSVExporter(Exporter):
    """Bulgu, TI ve istatistik tablolarını üç ayrı CSV dosyasına yazar."""

    name: ClassVar[str] = "csv"

    def export(self, payload: ExportPayload, output_dir: Path) -> list[Path]:
        self._prepare_output_dir(output_dir)

        written: list[Path] = [
            self._write_csv(
                self._target_path(payload, output_dir, "_findings.csv"),
                _FINDINGS_HEADER,
                self._findings_rows(payload.findings),
            ),
            self._write_csv(
                self._target_path(payload, output_dir, "_threat_intel.csv"),
                _THREAT_INTEL_HEADER,
                self._threat_intel_rows(payload),
            ),
            self._write_csv(
                self._target_path(payload, output_dir, "_statistics.csv"),
                _STATISTICS_HEADER,
                self._statistics_rows(payload.statistics),
            ),
        ]

        logger.info("CSV export'u oluşturuldu: %d dosya (%s)", len(written), output_dir)
        return written

    @staticmethod
    def _write_csv(output_path: Path, header: Sequence[str], rows: Iterable[Sequence[Any]]) -> Path:
        """Başlık + satırları tek bir CSV dosyasına yazar.

        ``newline=""``: csv modülünün gerektirdiği ayar. Verilmezse Windows'ta
        her satırın arasına boş satır girer (\\r\\r\\n).
        """
        try:
            with output_path.open("w", encoding=_CSV_ENCODING, newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(header)
                writer.writerows(rows)
        except OSError as exc:
            raise ExportError(f"CSV çıktısı yazılamadı: {output_path} ({exc})") from exc
        return output_path

    @staticmethod
    def _findings_rows(findings: Sequence[ThreatFinding]) -> list[tuple[Any, ...]]:
        """Bulgu başına bir satır üretir (gruplanmamış, ham)."""
        return [
            (
                finding.rule_id,
                finding.severity.value,
                finding.title,
                finding.source,
                finding.destination or "",
                finding.timestamp if finding.timestamp is not None else "",
                _epoch_to_iso(finding.timestamp),
                finding.description,
                _evidence_to_json(finding.evidence),
            )
            for finding in findings
        ]

    @staticmethod
    def _threat_intel_rows(payload: ExportPayload) -> list[tuple[Any, ...]]:
        """(IP x sağlayıcı) başına bir satır üretir.

        Uzlaşı alanları her satırda TEKRARLANIR (denormalize). Düz bir tabloda
        "IP başına bir kez" yazmanın yolu yoktur; tekrarlama, dosyayı hem
        süzülebilir hem de her satırı kendi başına anlamlı bırakır.
        """
        rows: list[tuple[Any, ...]] = []
        for summary in _prepare_threat_intel_for_template(payload.threat_intel):
            for result in summary.results:
                rows.append(
                    (
                        summary.ip,
                        summary.consensus_label,
                        summary.consensus_detail,
                        summary.total_providers,
                        summary.answered_providers,
                        summary.malicious_providers,
                        result.source,
                        _TRISTATE_LABELS[result.is_malicious],
                        result.raw_score if result.raw_score is not None else "",
                        result.confidence if result.confidence is not None else "",
                        # Kategoriler tek hücrede; virgül CSV ayracı olduğu için
                        # noktalı virgülle birleştirilir (aksi halde alan
                        # tırnaklanır ve okunabilirliği düşer).
                        "; ".join(result.categories),
                        result.last_seen.isoformat() if result.last_seen else "",
                        result.queried_at.isoformat() if result.queried_at else "",
                        result.provider_error_code.value if result.provider_error_code else "",
                        result.provider_error_message or "",
                    )
                )
        return rows

    @staticmethod
    def _statistics_rows(stats: GeneralStatistics) -> list[tuple[str, str, Any]]:
        """İstatistikleri (category, key, value) uzun biçimine düzleştirir."""
        rows: list[tuple[str, str, Any]] = [
            ("summary", "total_packets", stats.total_packets),
            ("summary", "total_bytes", stats.total_bytes),
            ("summary", "capture_duration_seconds", f"{stats.capture_duration:.6f}"),
            ("summary", "first_packet_time_epoch", stats.first_packet_time or ""),
            ("summary", "last_packet_time_epoch", stats.last_packet_time or ""),
            ("summary", "first_packet_time_iso", _epoch_to_iso(stats.first_packet_time)),
            ("summary", "last_packet_time_iso", _epoch_to_iso(stats.last_packet_time)),
        ]

        distributions = (
            ("protocol_distribution", stats.protocol_distribution),
            ("network_protocol_distribution", stats.network_protocol_distribution),
            ("transport_protocol_distribution", stats.transport_protocol_distribution),
            ("application_protocol_distribution", stats.application_protocol_distribution),
        )
        for category, distribution in distributions:
            # Rapordaki grafiklerle aynı sıra (çoktan aza) korunur ki iki
            # çıktıyı yan yana koyan analist aynı sırayı görsün.
            for key, value in sorted(distribution.items(), key=lambda kv: kv[1], reverse=True):
                rows.append((category, key, value))

        top_lists = (
            ("top_bandwidth_hosts", stats.top_bandwidth_hosts),
            ("top_source_ips", stats.top_source_ips),
            ("top_destination_ips", stats.top_destination_ips),
            ("top_tcp_ports", stats.top_tcp_ports),
            ("top_udp_ports", stats.top_udp_ports),
        )
        for category, entries in top_lists:
            for key, value in entries:
                rows.append((category, str(key), value))

        # Zaman çizelgesi ham çözünürlükte (bucket başına bir satır) yazılır.
        # Rapordaki tablo okunabilirlik için yeniden örneklenir; CSV'de bu
        # yapılmaz, çünkü buranın amacı veriyi başka bir araçta çizdirmektir.
        for bucket, packet_count in sorted(stats.timeline.items()):
            rows.append(("timeline", str(bucket), packet_count))

        return rows
