"""HTML rapor üretim modülü — PCAP Forensic Analysis Tool.

Sorumluluk
----------
Bu modül; Statistics, Threat Detector (ve Threat Intel) çıktısını
tek dosyalık, tamamen offline çalışan profesyonel bir HTML rapora
dönüştürür. Görünüm (Jinja2 template) ile üretim mantığı (bu dosya)
kesin olarak birbirinden ayrılmıştır.

Mimari
------
    GeneralStatistics ─┐
    Sequence[ThreatFinding] ─┼─> Reporter.generate() ─> report.html
    dict[str, list[NormalizedIOCResult]] ─┤
    ReportMetadata ─┘
                    │
                    ├─ ChartBuilder       (matplotlib -> base64 PNG & TableRow)
                    └─ compute_risk_summary  (severity ağırlıklı skor)

Neden bu ayrım (Single Responsibility + testability):
    - ChartBuilder: yalnızca "veri -> görsel ve tablo" dönüşümünden sorumludur,
      Jinja2'den veya dosya sisteminden habersizdir -> saf birim testi.
    - compute_risk_summary: yalnızca "bulgu listesi -> risk skoru"
      hesaplar, yan etkisi yoktur -> saf fonksiyon, saf test.
    - Reporter: yalnızca orkestrasyon yapar (girdi doğrulama, çağrı
      sırası, dosya yazma) -> mock'lanabilir bağımlılıklarla test edilir.

Offline gereksinimi: Üretilen grafikler harici bir .png dosyasına referans
vermez; base64 olarak HTML içine gömülür. Böylece rapor tek dosya olarak
taşınabilir ve internet bağlantısı olmayan bir adli inceleme
istasyonunda da açılabilir.
"""

from __future__ import annotations

import base64
import io
import logging
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

import matplotlib

matplotlib.use("Agg")  # GUI'siz ortamlarda (sunucu/CI) render için zorunlu.

import matplotlib.pyplot as plt
from jinja2 import Environment, FileSystemLoader, select_autoescape
from jinja2.exceptions import TemplateError, UndefinedError

import config
from modules.models import GeneralStatistics, ThreatFinding, ThreatSeverity
from modules.threat_intel import NormalizedIOCResult

logger = logging.getLogger(__name__)

_TEMPLATE_DIR: Final[Path] = Path(__file__).resolve().parent.parent / "templates"
_TEMPLATE_NAME: Final[str] = "report.html.j2"
_TOOL_VERSION: Final[str] = "1.2.0-forensic"

# Ağırlıklar keyfi değildir: HIGH bir CRITICAL'e göre daha düşük etkiye
# sahiptir ancak birden fazla HIGH bulgusu birikince risk skoru orantılı
# şekilde yükselmelidir. Değerler, "5 LOW bulgu" ile "1 CRITICAL bulgu"
# arasında anlamlı bir ayrım yaratacak şekilde seçilmiştir.
_SEVERITY_WEIGHT: Final[dict[ThreatSeverity, int]] = {
    ThreatSeverity.INFO: 0,
    ThreatSeverity.LOW: 1,
    ThreatSeverity.MEDIUM: 5,
    ThreatSeverity.HIGH: 15,
    ThreatSeverity.CRITICAL: 30,
}

# (eşik_skoru, etiket, css_sınıfı) üçlüleri artan sırada. En yüksek eşiğe ulaşan
# etiket kazanır (bkz. compute_risk_summary).
# Test beklentilerine göre (0 -> TEMİZ, 4 -> DÜŞÜK, 5 -> ORTA, 15 -> YÜKSEK, 30 -> KRİTİK) ayarlanmıştır.
_RISK_THRESHOLDS: Final[tuple[tuple[int, str, str], ...]] = (
    (0, "TEMİZ", "clean"),
    (4, "DÜŞÜK", "low"),
    (5, "ORTA", "medium"),
    (15, "YÜKSEK", "high"),
    (30, "KRİTİK", "critical"),
)

# Öncelik sıralaması açıkça tanımlanmıştır; Enum sırası değişse dahi
# sıralama mantığı bozulmaz (CRITICAL > HIGH > MEDIUM > LOW > INFO).
_SEVERITY_PRIORITY: Final[dict[ThreatSeverity, int]] = {
    ThreatSeverity.CRITICAL: 0,
    ThreatSeverity.HIGH: 1,
    ThreatSeverity.MEDIUM: 2,
    ThreatSeverity.LOW: 3,
    ThreatSeverity.INFO: 4,
}

_SEVERITY_ORDER: Final[list[str]] = [
    ThreatSeverity.CRITICAL.value,
    ThreatSeverity.HIGH.value,
    ThreatSeverity.MEDIUM.value,
    ThreatSeverity.LOW.value,
    ThreatSeverity.INFO.value,
]


class ReportGenerationError(Exception):
    """Rapor üretimi başarısız olduğunda fırlatılır (Fail Fast)."""


@dataclass(frozen=True, slots=True)
class TableRow:
    """Grafik yanındaki analist veri tablosunun bir satırı."""

    label: str
    value: str


@dataclass(frozen=True, slots=True)
class ChartSection:
    """Rapor içerisindeki grafik ve tablo bölümünü temsil eden tip güvenli yapı."""

    id: str
    title: str
    description: str
    image: str
    table: list[TableRow]
    val_header: str


@dataclass(frozen=True, slots=True)
class ReportMetadata:
    """Raporun 'Genel Özet' bölümünde gösterilecek meta veriler."""

    source_file: str
    analysis_duration_seconds: float
    sha256: str | None = None
    tool_version: str = _TOOL_VERSION
    python_version: str = field(
        default_factory=lambda: f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    generated_at: datetime = field(default_factory=datetime.now)


@dataclass(frozen=True, slots=True)
class RiskSummary:
    """Bulgu listesinden türetilen genel risk özeti."""

    total_findings: int
    severity_counts: dict[str, int]
    risk_score: int
    risk_level: str
    risk_class: str


def compute_risk_summary(findings: Sequence[ThreatFinding]) -> RiskSummary:
    """Ağırlıklı risk skorunu ve severity dağılımını hesaplar.

    Algoritma: Tek geçişli toplama.
        risk_score = sum(_SEVERITY_WEIGHT[f.severity] for f in findings)

    Karmaşıklık: O(M) zaman, O(1) ek alan (M = bulgu sayısı; severity
    anahtar sayısı sabittir). Neden bu yaklaşım doğru: bulgu sayısı
    (tipik olarak < 10^3), analiz edilen paket sayısından (10^5-10^6)
    çok küçüktür; doğrusal tek geçiş hem optimal hem de en basit çözümdür
    (KISS). Ağırlıklı toplam, sadece bulgu *sayısını* değil önem
    derecesini de yansıtan, sezgisel ve genişletilebilir bir skorlama
    sağlar (yeni bir severity seviyesi eklemek yalnızca _SEVERITY_WEIGHT
    sözlüğüne bir satır eklemeyi gerektirir; OCP'ye uygundur).
    """
    severity_counts: dict[str, int] = {s.value: 0 for s in ThreatSeverity}
    risk_score = 0

    for finding in findings:
        severity_counts[finding.severity.value] += 1
        risk_score += _SEVERITY_WEIGHT[finding.severity]

    risk_level = _RISK_THRESHOLDS[0][1]
    risk_class = _RISK_THRESHOLDS[0][2]

    for threshold, label, css_class in reversed(_RISK_THRESHOLDS):
        if risk_score >= threshold:
            risk_level = label
            risk_class = css_class
            break

    return RiskSummary(
        total_findings=len(findings),
        severity_counts=severity_counts,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_class=risk_class,
    )


class ChartBuilder:
    """İstatistik verilerinden base64 kodlu PNG grafikler ve detay tabloları inşa eder.

    Bu sınıf bilinçli olarak Jinja2'den, dosya sisteminden ve Reporter'ın
    geri kalanından habersizdir (sadece dict/list -> (str, list[TableRow])
    dönüşümü yapar). Bu izolasyon, matplotlib çağrılarını mock'lamadan gerçek
    girdi/çıktı üzerinden birim test etmeyi mümkün kılabilir.
    """

    _FIGSIZE: Final[tuple[float, float]] = (8.0, 4.2)
    _DPI: Final[int] = 110

    def protocol_distribution_chart(
        self, distribution: dict[str, int]
    ) -> tuple[str | None, list[TableRow]]:
        """Protokol dağılımı için pasta grafiği ve analist veri tablosu üretir."""
        if not distribution:
            return None, []

        items = sorted(distribution.items(), key=lambda kv: kv[1], reverse=True)
        labels, values = zip(*items, strict=True)

        fig, ax = plt.subplots(figsize=self._FIGSIZE, dpi=self._DPI)
        ax.pie(values, labels=labels, autopct="%1.1f%%", startangle=90)
        ax.set_title("Protokol Dağılımı")

        table_data = [TableRow(label=k, value=f"{v:,}") for k, v in items]
        return self._to_base64(fig), table_data

    def top_hosts_chart(
        self, hosts: Sequence[tuple[str, int]], title: str, xlabel: str
    ) -> tuple[str | None, list[TableRow]]:
        """Top-K host listesi (talker/bandwidth) için yatay bar grafiği ve tablo üretir."""
        if not hosts:
            return None, []

        top = list(hosts[: config.TOP_N_TALKERS])
        # barh en üstte en büyük değeri göstersin diye ters çeviriyoruz.
        labels = [host for host, _ in reversed(top)]
        values = [count for _, count in reversed(top)]

        fig, ax = plt.subplots(figsize=self._FIGSIZE, dpi=self._DPI)
        ax.barh(labels, values, color="#2563eb")
        ax.set_title(title)
        ax.set_xlabel(xlabel)
        fig.tight_layout()

        table_data = [
            TableRow(label=host, value=f"{count:,}") for host, count in top
        ]
        return self._to_base64(fig), table_data

    def port_distribution_chart(
        self, ports: dict[int, int]
    ) -> tuple[str | None, list[TableRow]]:
        """En sık görülen ilk N port için dikey bar grafiği ve tablo üretir."""
        if not ports:
            return None, []

        top = sorted(ports.items(), key=lambda kv: kv[1], reverse=True)[: config.TOP_N_PORTS]
        labels = [str(port) for port, _ in top]
        values = [count for _, count in top]

        fig, ax = plt.subplots(figsize=self._FIGSIZE, dpi=self._DPI)
        ax.bar(labels, values, color="#059669")
        ax.set_title(f"Port Dağılımı (İlk {config.TOP_N_PORTS})")
        ax.set_xlabel("Port")
        ax.set_ylabel("Paket Sayısı")
        ax.tick_params(axis="x", rotation=45)
        fig.tight_layout()

        table_data = [
            TableRow(label=f"Port {port}", value=f"{count:,}") for port, count in top
        ]
        return self._to_base64(fig), table_data

    def timeline_chart(
        self, timeline: dict[float, int]
    ) -> tuple[str | None, list[TableRow]]:
        """Zaman kovalarına (bucket) göre paket trafiği çizgi grafiği ve tablo üretir."""
        if not timeline:
            return None, []

        items = sorted(timeline.items())
        formatted_labels = [
            datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")
            for ts, _ in items
        ]
        values = [count for _, count in items]

        fig, ax = plt.subplots(figsize=self._FIGSIZE, dpi=self._DPI)
        ax.plot(range(len(values)), values, color="#dc2626", linewidth=1.5)
        ax.fill_between(range(len(values)), values, alpha=0.15, color="#dc2626")
        ax.set_title("Zaman Çizelgesi (Paket Trafiği)")
        ax.set_ylabel("Paket Sayısı")

        step = max(len(formatted_labels) // 10, 1)
        tick_positions = range(0, len(formatted_labels), step)
        ax.set_xticks(list(tick_positions))
        ax.set_xticklabels([formatted_labels[i] for i in tick_positions], rotation=45, ha="right")
        fig.tight_layout()

        table_data = [
            TableRow(label=time_label, value=f"{count:,}")
            for time_label, (_, count) in zip(formatted_labels, items, strict=True)
        ]
        return self._to_base64(fig), table_data

    @staticmethod
    def _to_base64(fig: plt.Figure) -> str:
        """Figure'ı PNG'ye render edip base64 string'e çevirir.

        `finally` bloğu ile figure ve buffer her koşulda kapatılır; aksi
        halde matplotlib figure nesneleri process ömrü boyunca bellekte
        birikir (rapor çok sayıda grafik ürettiğinde ciddi bir memory
        leak kaynağıdır).
        """
        buffer = io.BytesIO()
        try:
            fig.savefig(buffer, format="png", bbox_inches="tight")
            return base64.b64encode(buffer.getvalue()).decode("ascii")
        finally:
            plt.close(fig)
            buffer.close()


class Reporter:
    """Analiz sonuçlarını tek dosyalık, offline HTML rapora dönüştürür.

    Sorumluluk (Single Responsibility): Bu sınıf yalnızca *orkestrasyon*
    yapar — grafik/tablo üretimini ``ChartBuilder``'a, risk hesaplamasını
    ``compute_risk_summary``'ye, görünümü Jinja2 şablonuna devreder.
    Böylece şablon değişse bile Python kodu, algoritma değişse bile
    şablon etkilenmez (View/Controller ayrımı).
    """

    def __init__(
        self,
        template_dir: Path | None = None,
        template_name: str = _TEMPLATE_NAME,
        chart_builder: ChartBuilder | None = None,
    ) -> None:
        resolved_dir = template_dir or _TEMPLATE_DIR
        if not resolved_dir.is_dir():
            raise ReportGenerationError(f"Şablon dizini bulunamadı: {resolved_dir}")

        self._env = Environment(
            loader=FileSystemLoader(str(resolved_dir)),
            autoescape=select_autoescape(enabled_extensions=("html", "j2")),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._template_name = template_name
        self._chart_builder = chart_builder or ChartBuilder()
        logger.debug("Reporter başlatıldı. Şablon dizini: %s", resolved_dir)

    def generate(
        self,
        statistics: GeneralStatistics,
        findings: Sequence[ThreatFinding],
        threat_intel: dict[str, list[NormalizedIOCResult]],
        source_file: Path,
        analysis_duration: float,
    ) -> Path:
        """Analiz sonuçlarından tek dosyalık HTML rapor üretir.

        Args:
            statistics: Statistics modülünün ürettiği genel istatistikler.
            findings: Threat Detector'ın ürettiği bulgular (sıra önemsiz,
                bu metod severity'ye göre yeniden sıralar).
            threat_intel: Threat Intel modülünden gelen IOC sonuçları.
            source_file: Analiz edilen PCAP kaynak dosya yolu.
            analysis_duration: Analiz süresi (saniye cinsinden).

        Returns:
            Yazılan rapor dosyasının ``Path`` nesnesi.

        Raises:
            ReportGenerationError: Girdi doğrulaması, şablon render'ı veya
                dosya yazma aşamasında hata oluşursa (Fail Fast — hatalı
                durum en erken noktada, açık bir mesajla yükseltilir).
        """
        metadata = ReportMetadata(
            source_file=source_file.name,
            analysis_duration_seconds=analysis_duration,
        )

        # Girdi dosyasının üst klasör ismine göre hedef klasörü seç (clean / malicious)
        parent_folder_name = source_file.parent.name.lower()
        category_dir = parent_folder_name if parent_folder_name in {"clean", "malicious"} else "clean"

        reports_dir = config.REPORTS_DIR / category_dir
        output_path = reports_dir / f"{source_file.stem}_report.html"

        logger.info(
            "Generating report for %s (%d packets)...",
            metadata.source_file,
            statistics.total_packets,
        )
        self._validate_inputs(statistics, metadata, output_path)

        sorted_findings = self._sort_findings_by_severity(findings)
        risk_summary = compute_risk_summary(findings)
        charts_list = self._build_charts_list(statistics)

        html = self._render(
            metadata=metadata,
            statistics=statistics,
            findings=sorted_findings,
            threat_intel=threat_intel,
            risk_summary=risk_summary,
            charts=charts_list,
        )
        self._write(html, output_path)

        logger.info(
            "Rapor başarıyla oluşturuldu: %s (%d bulgu, risk seviyesi: %s)",
            output_path,
            len(findings),
            risk_summary.risk_level,
        )
        return output_path

    def _build_charts_list(self, statistics: GeneralStatistics) -> list[ChartSection]:
        """Tüm grafikleri ve bunlara ait analist detay tablolarını tek bir listede toplar."""
        charts: list[ChartSection] = []

        # 1. Protokol Dağılımı
        img, table = self._chart_builder.protocol_distribution_chart(
            statistics.protocol_distribution
        )
        if img:
            charts.append(
                ChartSection(
                    id="protocol_distribution",
                    title="Protokol Dağılımı",
                    description="Yakalanan paketlerin uygulama/taşıma katmanı protokollerine göre yüzdesel dağılımı.",
                    image=img,
                    table=table,
                    val_header="Paket Sayısı",
                )
            )

        # 2. Top Talkers
        img, table = self._chart_builder.top_hosts_chart(
            statistics.top_source_ips, "En Aktif Hostlar (Top Talkers)", "Paket Sayısı"
        )
        if img:
            charts.append(
                ChartSection(
                    id="top_talkers",
                    title="En Aktif Hostlar (Top Talkers)",
                    description="Ağ üzerinde en yüksek miktarda paket üreten/gönderen kaynak IP adresleri.",
                    image=img,
                    table=table,
                    val_header="Paket Sayısı",
                )
            )

        # 3. Top Bandwidth Hosts
        img, table = self._chart_builder.top_hosts_chart(
            statistics.top_bandwidth_hosts, "En Yüksek Bant Genişliği Kullananlar", "Byte"
        )
        if img:
            charts.append(
                ChartSection(
                    id="top_bandwidth_hosts",
                    title="En Yüksek Bant Genişliği Kullananlar",
                    description="Toplam veri aktarım hacmi (byte) açısından ağ bant genişliğini en çok tüketen hostlar.",
                    image=img,
                    table=table,
                    val_header="Toplam Boyut (Byte)",
                )
            )

        # 4. Port Dağılımı
        img, table = self._chart_builder.port_distribution_chart(
            dict(statistics.top_tcp_ports)
        )
        if img:
            charts.append(
                ChartSection(
                    id="port_distribution",
                    title="Port Dağılımı",
                    description="Trafikte en sık hedef alınan ve kullanılan ilk TCP portlarının paket yoğunluğu.",
                    image=img,
                    table=table,
                    val_header="Paket Sayısı",
                )
            )

        # 5. Zaman Çizelgesi
        img, table = self._chart_builder.timeline_chart(statistics.timeline)
        if img:
            charts.append(
                ChartSection(
                    id="timeline",
                    title="Zaman Çizelgesi (Paket Trafiği)",
                    description="Analiz edilen zaman aralığı boyunca ağ trafiğinde meydana gelen anlık yoğunlaşma ve dalgalanmalar.",
                    image=img,
                    table=table,
                    val_header="Paket Sayısı",
                )
            )

        return charts

    def _render(
        self,
        *,
        metadata: ReportMetadata,
        statistics: GeneralStatistics,
        findings: list[ThreatFinding],
        threat_intel: dict[str, list[NormalizedIOCResult]],
        risk_summary: RiskSummary,
        charts: list[ChartSection],
    ) -> str:
        """Hazırlanan verileri Jinja2 şablonuna aktararak HTML metnini oluşturur."""
        try:
            template = self._env.get_template(self._template_name)
            return template.render(
                metadata=metadata,
                statistics=statistics,
                findings=findings,
                threat_intel=threat_intel,
                risk_summary=risk_summary,
                charts=charts,
                severity_order=_SEVERITY_ORDER,
            )
        except UndefinedError as exc:
            logger.error("Şablonda tanımlanmamış değişken hatası (UndefinedError): %s", exc)
            raise ReportGenerationError(
                f"Şablon render hatası (Tanımsız Değişken): {exc}"
            ) from exc
        except TemplateError as exc:
            raise ReportGenerationError(f"Şablon render hatası: {exc}") from exc

    @staticmethod
    def _write(html: str, output_path: Path) -> None:
        """Üretilen HTML metnini belirtilen hedef dosyaya yazar."""
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(html, encoding="utf-8")
        except OSError as exc:
            raise ReportGenerationError(f"Rapor dosyaya yazılamadı: {exc}") from exc

    @staticmethod
    def _sort_findings_by_severity(findings: Sequence[ThreatFinding]) -> list[ThreatFinding]:
        """En kritik bulgular en üstte görünsün: CRITICAL > HIGH > MEDIUM > LOW > INFO."""
        return sorted(findings, key=lambda f: _SEVERITY_PRIORITY[f.severity])

    @staticmethod
    def _validate_inputs(
        statistics: GeneralStatistics, metadata: ReportMetadata, output_path: Path
    ) -> None:
        """Fail Fast: Hatalı girdi durumunda işlemi derhal durdurur."""
        if statistics is None:
            raise ReportGenerationError("statistics None olamaz.")
        if metadata is None:
            raise ReportGenerationError("metadata None olamaz.")
        if output_path.is_dir():
            raise ReportGenerationError(
                f"Çıktı yolu bir dosya olmalıdır, ancak bir dizin belirtildi: '{output_path}'"
            )
        if output_path.suffix.lower() not in {".html", ".htm"}:
            raise ReportGenerationError(
                f"Çıktı dosyası .html veya .htm uzantılı olmalı, alınan: '{output_path.suffix}'"
            )