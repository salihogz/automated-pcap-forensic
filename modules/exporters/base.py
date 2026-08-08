# modules/exporters/base.py
"""
Automated PCAP Forensic Analysis Tool - Export katmanının ortak sözleşmesi.

Her export biçimi (JSON / CSV / PDF) AYNI girdiyi tüketir: ``ExportPayload``.
Bu, biçimlerin birbirinden bağımsız kalmasını sağlar (yeni bir biçim eklemek
mevcutları değiştirmez -- OCP) ve daha önemlisi, pahalı ya da hataya açık
türetmelerin YALNIZCA BİR KEZ yapılmasını garanti eder:

* ``sha256`` -- kaynak capture'ın tamamı okunarak hesaplanır. Her export
  kendi hesaplasaydı 1,3 GB'lık bir delil dosyası dört kez okunurdu.
* ``risk_summary`` -- eşik tablosu bir API sözleşmesidir (bkz. reporter.py);
  her biçimin kendi hesabını yapması, aynı capture için farklı risk seviyesi
  bildiren iki çıktı üretme riski demektir.

NEDEN reporter.py'nin "private" yardımcıları import ediliyor:
``_prepare_findings_for_template`` / ``_prepare_threat_intel_for_template``
gibi fonksiyonlar sunum katmanının tek doğruluk kaynağıdır. Özellikle TI
uzlaşısı (consensus), "cevap verememe"yi "temiz" saymama kuralını taşır ve
bu kural daha önce bir kez sessizce bozulmuştu (bkz. reporter.py'deki uzun
açıklama). PDF çıktısının kendi uzlaşı hesabını yapması, aynı IP için HTML'de
"KISMİ TEMİZ", PDF'te "TEMİZ" yazan iki adli belge üretebilirdi. Alt çizgi
burada "modül dışına kapalı" değil, "``modules`` paketi dışına kapalı"
anlamında okunmalıdır.
"""
import logging
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import ClassVar

import config
from modules.models import GeneralStatistics, ThreatFinding
from modules.reporter import RiskSummary, _compute_sha256, compute_risk_summary
from modules.threat_intel import NormalizedIOCResult

logger = logging.getLogger(__name__)


class ExportError(Exception):
    """Bir export biçimi çıktı üretemediğinde fırlatılır (Fail Fast)."""


@dataclass(frozen=True, slots=True)
class ExportPayload:
    """Tüm export biçimlerinin tükettiği, değişmez analiz sonucu paketi.

    ``frozen=True``: bir export biçiminin payload'ı değiştirip sonrakini
    etkilemesi mümkün olmamalıdır (chain of custody -- aynı analizden üretilen
    JSON, CSV ve PDF birebir aynı veriyi anlatmak zorundadır).

    Attributes:
        source_file: Analiz edilen capture'ın yolu.
        statistics: Statistics motorunun ürettiği genel istatistikler.
        findings: Tespit motorunun ürettiği HAM bulgular (gruplanmamış,
            sıralanmamış). Sunum amaçlı gruplama biçimlerin kendi işidir.
        threat_intel: IP -> sağlayıcı sonuçları eşlemesi.
        risk_summary: Ham bulgu listesinden hesaplanan risk özeti.
        analysis_duration_seconds: Analizin toplam süresi.
        sha256: Kaynak dosyanın SHA-256 özeti; hesaplanamadıysa None
            (Fail Soft -- eksik bir bütünlük özeti tüm export'u engellememeli,
            ancak çıktıda "hesaplanamadı" olarak görünür, sessizce atlanmaz).
        generated_at: Çıktının üretildiği an. Saat dilimi BİLİNÇLİ olarak
            taşınır: adli bir belgede "14:32" hangi dilimde olduğu
            yazılmadıkça kanıt değeri taşımaz.
        tool_version: Üretimi yapan araç sürümü (config.TOOL_VERSION).
    """

    source_file: Path
    statistics: GeneralStatistics
    findings: tuple[ThreatFinding, ...]
    threat_intel: dict[str, list[NormalizedIOCResult]]
    risk_summary: RiskSummary
    analysis_duration_seconds: float
    sha256: str | None
    generated_at: datetime
    tool_version: str

    @classmethod
    def build(
        cls,
        *,
        statistics: GeneralStatistics,
        findings: Sequence[ThreatFinding],
        threat_intel: dict[str, list[NormalizedIOCResult]],
        source_file: Path,
        analysis_duration: float,
        sha256: str | None = None,
    ) -> ExportPayload:
        """Analiz sonuçlarından payload üretir; türetilmiş alanları bir kez hesaplar.

        Args:
            sha256: Çağıran taraf özeti zaten hesapladıysa (ör. main.py aynı
                özeti HTML raporuna da vereceği için) buradan geçirilir ve
                dosya yeniden okunmaz. Verilmezse burada hesaplanır.
        """
        return cls(
            source_file=source_file,
            statistics=statistics,
            findings=tuple(findings),
            threat_intel=threat_intel,
            # Risk skoru DAİMA ham, gruplanmamış bulgu listesinden hesaplanır --
            # aksi halde tekrarlayan tespitler tek olay gibi sayılıp skor düşer
            # (Reporter.generate() ile aynı kural).
            risk_summary=compute_risk_summary(findings),
            analysis_duration_seconds=analysis_duration,
            sha256=sha256 if sha256 is not None else _compute_sha256(source_file),
            # astimezone(): yerel saat + UTC farkı. Naive datetime yerine bunun
            # seçilmesinin sebebi, çıktının ISO biçiminde "+03:00" gibi bir ofset
            # taşıması; farklı dilimdeki bir analist zaman damgasını doğru okur.
            generated_at=datetime.now().astimezone(),
            tool_version=config.TOOL_VERSION,
        )


class Exporter(ABC):
    """Bir export biçiminin ortak arayüzü.

    Alt sınıflar yalnızca ``export()`` yazar; biçim adı ve dosya adı
    türetmesi burada standartlaşır. Yeni bir biçim eklemek için mevcut
    hiçbir sınıfı değiştirmek gerekmez (OCP).
    """

    #: CLI'da ve loglarda kullanılan biçim adı ("json", "csv", "pdf").
    name: ClassVar[str]

    @abstractmethod
    def export(self, payload: ExportPayload, output_dir: Path) -> list[Path]:
        """Payload'ı ``output_dir`` içine yazar ve yazılan dosyaları döndürür.

        Dönüş tipi tek bir ``Path`` değil LİSTEDİR: CSV biçimi doğası gereği
        birden çok dosya üretir (tek bir CSV'ye farklı şekilli tablolar
        sığmaz). Tek dosya üreten biçimler tek elemanlı liste döndürür;
        böylece çağıran taraf biçimler arasında ayrım yapmak zorunda kalmaz.

        Raises:
            ExportError: Çıktı üretilemezse (yazma hatası, eksik opsiyonel
                bağımlılık, serileştirilemeyen veri).
        """

    @staticmethod
    def _target_path(payload: ExportPayload, output_dir: Path, suffix: str) -> Path:
        """`<output_dir>/<capture-adı><suffix>` biçiminde hedef dosya yolu üretir.

        Örn. suffix="_report.json" -> "demo_capture_report.json". HTML raporu
        (`<stem>_report.html`) ile aynı adlandırma ailesini kullanır ki bir
        capture'ın tüm çıktıları klasörde yan yana sıralansın.
        """
        return output_dir / f"{payload.source_file.stem}{suffix}"

    @staticmethod
    def _prepare_output_dir(output_dir: Path) -> None:
        """Hedef dizini oluşturur; oluşturulamazsa ExportError'a çevirir."""
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ExportError(f"Çıktı dizini oluşturulamadı: {output_dir} ({exc})") from exc
