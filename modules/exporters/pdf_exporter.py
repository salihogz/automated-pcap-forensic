# modules/exporters/pdf_exporter.py
"""
Automated PCAP Forensic Analysis Tool - PDF export.

HTML raporun bir kopyası DEĞİLDİR; basılmak, imzalanmak ve bir dosyaya
eklenmek üzere tasarlanmış ayrı bir belgedir. Farklar bilinçlidir:

* Sayfa altında "Sayfa X / Y" bulunur. Adli bir belgede sayfa
  numaralandırması, belgenin eksiksiz teslim edildiğinin kanıtıdır;
  toplam sayfa sayısı olmadan bir sayfanın çıkarıldığı anlaşılamaz.
* Bulgular, HTML raporda olduğu gibi GRUPLANMIŞ ve önem sırasına dizilmiş
  hâlde yer alır (aynı `_group_recurring_findings` çağrılır). JSON/CSV ham
  veriyi taşır; bu belge insan içindir, aynı tespitin 400 tekrarını 400 satır
  olarak basmak okunabilirliği yok eder.
* Grafikler, HTML raporla AYNI `build_chart_sections()` çağrısından gelir --
  iki çıktının farklı grafikler göstermesi "hangisi eksik?" sorusunu doğurur.
* Renkler HTML'deki koyu tema değerlerinden farklıdır: rapor ekranda koyu
  zeminde okunur, PDF beyaz kâğıtta. Aynı hex değerleri (ör. #22c55e)
  beyaz üzerinde yeterli kontrast vermez.

ReportLab OPSİYONEL bir bağımlılık gibi ele alınır: kurulu değilse yalnızca
PDF biçimi devre dışı kalır ve net bir hata mesajı verilir; HTML/JSON/CSV
çıktıları etkilenmez (bkz. parser.py'deki opsiyonel Scapy katmanı deseni).
"""
import base64
import io
import logging
from pathlib import Path
from typing import Any, ClassVar, Final
from xml.sax.saxutils import escape

import matplotlib

from modules.exporters.base import Exporter, ExportError, ExportPayload
from modules.reporter import (
    _SEVERITY_PRIORITY,
    ChartBuilder,
    _group_recurring_findings,
    _prepare_findings_for_template,
    _prepare_statistics_for_template,
    _prepare_threat_intel_for_template,
    build_chart_sections,
)

logger = logging.getLogger(__name__)

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFError, TTFont
    from reportlab.pdfgen import canvas as pdf_canvas
    from reportlab.platypus import (
        Image,
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    _REPORTLAB_IMPORT_ERROR: str | None = None
except ImportError as exc:  # pragma: no cover - kurulu ortamda tetiklenmez
    _REPORTLAB_IMPORT_ERROR = str(exc)


# ======================================================================
# YAZI TİPİ
# ======================================================================
# ReportLab'in gömülü Helvetica'sı WinAnsi (cp1252) kodlamasını kullanır ve
# Türkçe alfabenin ğ, Ğ, ş, Ş, ı, İ harflerini İÇERMEZ -- bu harfler PDF'te
# boş kutu ya da yanlış karakter olarak çıkar. Projenin tüm metinleri Türkçe
# olduğu için bu, kabul edilebilir bir kayıp değildir.
#
# Çözüm: tam Unicode kapsamına sahip DejaVu Sans'ı gömmek. Yeni bir bağımlılık
# GEREKMEZ -- DejaVu, matplotlib'in varsayılan yazı tipidir ve zaten kurulu bir
# runtime bağımlılığı olan matplotlib ile birlikte gelir.
_FONT_REGULAR: Final[str] = "DejaVuSans"
_FONT_BOLD: Final[str] = "DejaVuSans-Bold"

# DejaVu bulunamazsa (matplotlib kurulumu budanmışsa) belge yine de üretilir,
# yalnızca bazı Türkçe harfler bozulur. Fail Soft: eksik bir yazı tipi
# yüzünden adli çıktıyı hiç üretmemek daha kötü bir sonuçtur; durum loglanır.
_FALLBACK_FONT_REGULAR: Final[str] = "Helvetica"
_FALLBACK_FONT_BOLD: Final[str] = "Helvetica-Bold"

_fonts_ready: bool | None = None


def _register_fonts() -> tuple[str, str]:
    """DejaVu Sans'ı ReportLab'e kaydeder; (normal, kalın) yazı tipi adlarını döndürür.

    Kayıt süreç ömrü boyunca bir kez yapılır (ReportLab global bir kayıt
    defteri tutar); sonuç `_fonts_ready` içinde önbelleklenir.
    """
    global _fonts_ready

    if _fonts_ready is True:
        return _FONT_REGULAR, _FONT_BOLD
    if _fonts_ready is False:
        return _FALLBACK_FONT_REGULAR, _FALLBACK_FONT_BOLD

    font_dir = Path(matplotlib.get_data_path()) / "fonts" / "ttf"
    try:
        pdfmetrics.registerFont(TTFont(_FONT_REGULAR, str(font_dir / "DejaVuSans.ttf")))
        pdfmetrics.registerFont(TTFont(_FONT_BOLD, str(font_dir / "DejaVuSans-Bold.ttf")))
        # <b> etiketinin Paragraph içinde doğru kalın yüzü seçebilmesi için aile kaydı.
        pdfmetrics.registerFontFamily(_FONT_REGULAR, normal=_FONT_REGULAR, bold=_FONT_BOLD)
    except (OSError, TTFError) as exc:
        logger.warning(
            "DejaVu Sans yazı tipi kaydedilemedi (%s). PDF, Türkçe karakterleri "
            "eksik gösterebilen Helvetica ile üretilecek.",
            exc,
        )
        _fonts_ready = False
        return _FALLBACK_FONT_REGULAR, _FALLBACK_FONT_BOLD

    _fonts_ready = True
    return _FONT_REGULAR, _FONT_BOLD


# ======================================================================
# GÖRSEL SABİTLER
# ======================================================================
# Beyaz kâğıt için koyulaştırılmış önem derecesi renkleri (HTML raporun koyu
# tema paletiyle aynı renk ailesi, farklı ton -- bkz. modül docstring'i).
_SEVERITY_COLORS: Final[dict[str, str]] = {
    "CRITICAL": "#b91c1c",
    "HIGH": "#c2410c",
    "MEDIUM": "#a16207",
    "LOW": "#15803d",
    "INFO": "#0369a1",
}

# TI uzlaşı etiketlerinin ciddiyet sırası: en kaygı verici satır en üstte.
# "TEMİZ" en sonda çünkü uzun bir IP listesinde analistin ilk görmesi
# gereken şey, temiz çıkan IP'ler değildir.
_CONSENSUS_ORDER: Final[dict[str, int]] = {
    "ZARARLI": 0,
    "ÇELİŞKİLİ": 1,
    "KISMİ TEMİZ": 2,
    "VERİ YOK": 3,
    "TEMİZ": 4,
}

_PAGE_MARGIN: Final[float] = 15  # mm cinsinden; _build() içinde mm ile çarpılır
_MAX_CHART_HEIGHT_MM: Final[float] = 95.0


def _esc(value: Any) -> str:
    """Değeri Paragraph'ın mini-XML'i için güvenli metne çevirir.

    Paragraph içeriği işaretleme olarak ayrıştırılır; kaçırılmayan bir "&" ya
    da "<" tüm belgenin üretimini bozar. Kanıt alanları ve alan adları dış
    kaynaklıdır (capture'dan gelir), dolayısıyla güvenilmez girdi sayılmalıdır.
    """
    if value is None:
        return ""
    return escape(str(value))


class PDFExporter(Exporter):
    """Analiz sonucunu basılmaya uygun, sayfa numaralı tek bir PDF'e yazar."""

    name: ClassVar[str] = "pdf"

    def export(self, payload: ExportPayload, output_dir: Path) -> list[Path]:
        if _REPORTLAB_IMPORT_ERROR is not None:
            raise ExportError(
                "PDF export'u için 'reportlab' paketi gerekli, ancak import edilemedi "
                f"({_REPORTLAB_IMPORT_ERROR}). Kurulum: pip install -r requirements.txt"
            )

        self._prepare_output_dir(output_dir)
        output_path = self._target_path(payload, output_dir, "_report.pdf")

        regular, bold = _register_fonts()
        styles = self._build_styles(regular, bold)

        document = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            leftMargin=_PAGE_MARGIN * mm,
            rightMargin=_PAGE_MARGIN * mm,
            topMargin=_PAGE_MARGIN * mm,
            bottomMargin=(_PAGE_MARGIN + 5) * mm,
            title=f"PCAP Adli Analiz Raporu - {payload.source_file.name}",
            author="Automated PCAP Forensic Analysis Tool",
            subject="Network forensic analysis report",
        )

        story = self._build_story(payload, styles, document.width)

        try:
            document.build(story, canvasmaker=_numbered_canvas_factory(regular))
        except OSError as exc:
            raise ExportError(f"PDF çıktısı yazılamadı: {output_path} ({exc})") from exc

        logger.info("PDF export'u oluşturuldu: %s", output_path)
        return [output_path]

    # ------------------------------------------------------------------
    # Stiller
    # ------------------------------------------------------------------
    @staticmethod
    def _build_styles(regular: str, bold: str) -> dict[str, ParagraphStyle]:
        """Belgede kullanılan paragraf stillerini üretir.

        `getSampleStyleSheet()` yerine elle tanımlanıyor: hazır stiller
        Helvetica'ya sabitlenmiş durumda ve Türkçe karakter sorununu geri
        getirirdi (bkz. yazı tipi bölümü).
        """
        return {
            "title": ParagraphStyle(
                "title", fontName=bold, fontSize=18, leading=22, spaceAfter=2,
                textColor=colors.HexColor("#0f172a"),
            ),
            "subtitle": ParagraphStyle(
                "subtitle", fontName=regular, fontSize=10, leading=13,
                textColor=colors.HexColor("#475569"), spaceAfter=10,
            ),
            "heading": ParagraphStyle(
                "heading", fontName=bold, fontSize=12.5, leading=16, spaceBefore=12,
                spaceAfter=5, textColor=colors.HexColor("#1e3a8a"),
            ),
            "body": ParagraphStyle(
                "body", fontName=regular, fontSize=9, leading=12,
                textColor=colors.HexColor("#0f172a"),
            ),
            "muted": ParagraphStyle(
                "muted", fontName=regular, fontSize=8, leading=10.5,
                textColor=colors.HexColor("#475569"),
            ),
            "cell": ParagraphStyle(
                "cell", fontName=regular, fontSize=7.5, leading=9.5,
                textColor=colors.HexColor("#0f172a"),
            ),
            "cell_bold": ParagraphStyle(
                "cell_bold", fontName=bold, fontSize=7.5, leading=9.5,
                textColor=colors.HexColor("#0f172a"),
            ),
        }

    # ------------------------------------------------------------------
    # Belge akışı
    # ------------------------------------------------------------------
    def _build_story(
        self, payload: ExportPayload, styles: dict[str, ParagraphStyle], width: float
    ) -> list[Any]:
        """Belgenin tüm bölümlerini sırayla tek bir flowable listesine dizer."""
        story: list[Any] = []
        story += self._header_section(payload, styles, width)
        story += self._risk_section(payload, styles, width)
        story += self._traffic_section(payload, styles, width)
        story += self._findings_section(payload, styles, width)
        story += self._threat_intel_section(payload, styles, width)
        story += self._charts_section(payload, styles, width)
        return story

    def _header_section(
        self, payload: ExportPayload, styles: dict[str, ParagraphStyle], width: float
    ) -> list[Any]:
        """Başlık + delil (chain of custody) bilgileri."""
        rows = [
            ("Kaynak Dosya", payload.source_file.name),
            # SHA-256 tek satıra sığmaz; Paragraph içinde sarılması için
            # aşağıda hücre paragrafa çevriliyor.
            ("SHA-256", payload.sha256 or "Hesaplanamadı"),
            ("Üretim Zamanı", payload.generated_at.strftime("%d.%m.%Y %H:%M:%S %z")),
            ("Analiz Süresi", f"{payload.analysis_duration_seconds:.2f} sn"),
            ("Araç Sürümü", payload.tool_version),
        ]
        return [
            Paragraph("PCAP ADLİ ANALİZ RAPORU", styles["title"]),
            Paragraph(
                "Otomatik ağ trafiği adli analiz belgesi — Digital Forensics &amp; Incident Response",
                styles["subtitle"],
            ),
            Paragraph("1. Delil Bilgileri", styles["heading"]),
            self._key_value_table(rows, styles, width),
        ]

    def _risk_section(
        self, payload: ExportPayload, styles: dict[str, ParagraphStyle], width: float
    ) -> list[Any]:
        """Risk seviyesi, ağırlıklı skor ve önem derecesi dağılımı."""
        summary = payload.risk_summary
        severity_row = [Paragraph("<b>Önem</b>", styles["cell"])]
        count_row = [Paragraph("<b>Adet</b>", styles["cell"])]
        for severity, count in summary.severity_counts.items():
            severity_row.append(
                Paragraph(
                    f'<font color="{_SEVERITY_COLORS.get(severity, "#0f172a")}"><b>{_esc(severity)}</b></font>',
                    styles["cell"],
                )
            )
            count_row.append(Paragraph(str(count), styles["cell"]))

        distribution = Table([severity_row, count_row], colWidths=[width / 6.0] * 6)
        distribution.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )

        level_color = _SEVERITY_COLORS.get(summary.risk_class, "#0f172a")
        return [
            Paragraph("2. Risk Özeti", styles["heading"]),
            self._key_value_table(
                [
                    ("Risk Seviyesi", f'<font color="{level_color}"><b>{_esc(summary.risk_level)}</b></font>'),
                    # Skor sınırsız bir ağırlıklı toplamdır (CRITICAL 30, HIGH 15,
                    # MEDIUM 5, LOW 1); 100'lük bir ölçek DEĞİLDİR. Belgede bu
                    # açıkça yazılmazsa "95" değeri yüzde sanılır.
                    ("Risk Skoru", f"{summary.risk_score} (ağırlıklı toplam, üst sınırı yoktur)"),
                    ("Toplam Bulgu", str(summary.total_findings)),
                ],
                styles,
                width,
                pre_escaped=True,
            ),
            Spacer(1, 6),
            distribution,
        ]

    def _traffic_section(
        self, payload: ExportPayload, styles: dict[str, ParagraphStyle], width: float
    ) -> list[Any]:
        """Trafik özeti kartlarının PDF karşılığı (HTML raporla aynı değerler)."""
        stats = _prepare_statistics_for_template(payload.statistics)
        rows = [
            ("Toplam Paket", f"{stats['total_packets']:,}"),
            ("Toplam Boyut", stats["total_bytes_formatted"]),
            ("Capture Süresi", stats["duration_formatted"]),
            ("İlk Paket", stats["start_time_formatted"]),
            ("Son Paket", stats["end_time_formatted"]),
            ("IPv4 / IPv6", f"{stats['ipv4_count']:,} / {stats['ipv6_count']:,}"),
            ("TCP / UDP", f"{stats['tcp_count']:,} / {stats['udp_count']:,}"),
            # HTTPS iki taşıma üzerinde koşar: TLS (TCP) ve QUIC (UDP/HTTP-3).
            ("TLS / QUIC (HTTPS)", f"{stats['tls_count']:,} / {stats['quic_count']:,}"),
            ("HTTP / DNS", f"{stats['http_count']:,} / {stats['dns_count']:,}"),
            ("En Aktif Kaynak IP", stats["top_source_ip"] or "—"),
        ]
        return [
            Paragraph("3. Trafik Özeti", styles["heading"]),
            self._key_value_table(rows, styles, width),
        ]

    def _findings_section(
        self, payload: ExportPayload, styles: dict[str, ParagraphStyle], width: float
    ) -> list[Any]:
        """Tehdit bulguları tablosu (gruplanmış + önem sırasına dizilmiş)."""
        story: list[Any] = [Paragraph("4. Tehdit Bulguları", styles["heading"])]

        if not payload.findings:
            story.append(
                Paragraph(
                    "Tespit motorunun kuralları bu capture üzerinde bulgu üretmedi. "
                    "Bu, trafiğin zararsız olduğunun KANITI DEĞİLDİR: yalnızca "
                    "tanımlı kuralların eşiklerini aşan bir davranış görülmediği "
                    "anlamına gelir.",
                    styles["body"],
                )
            )
            return story

        display = sorted(
            _group_recurring_findings(payload.findings),
            key=lambda finding: _SEVERITY_PRIORITY[finding.severity],
        )
        rows = _prepare_findings_for_template(display, payload.statistics.ip_hostname_map)

        header = [
            Paragraph("<b>Önem</b>", styles["cell_bold"]),
            Paragraph("<b>Kural</b>", styles["cell_bold"]),
            Paragraph("<b>Kaynak → Hedef</b>", styles["cell_bold"]),
            Paragraph("<b>Zaman</b>", styles["cell_bold"]),
            Paragraph("<b>Açıklama ve Kanıt</b>", styles["cell_bold"]),
        ]
        table_data: list[list[Any]] = [header]

        for row in rows:
            severity = row["severity"].value
            color = _SEVERITY_COLORS.get(severity, "#0f172a")
            endpoint = _esc(row["source_display"])
            if row["destination_display"]:
                endpoint += f" →<br/>{_esc(row['destination_display'])}"

            evidence_lines = "<br/>".join(
                f'<font color="#475569">{_esc(label)}:</font> {_esc(value)}'
                for label, value in row["evidence_display"]
            )
            detail = f"<b>{_esc(row['title'])}</b><br/>{_esc(row['description'])}"
            if evidence_lines:
                detail += f"<br/>{evidence_lines}"

            table_data.append(
                [
                    Paragraph(f'<font color="{color}"><b>{_esc(severity)}</b></font>', styles["cell"]),
                    Paragraph(_esc(row["rule_id"]), styles["cell"]),
                    Paragraph(endpoint, styles["cell"]),
                    Paragraph(_esc(row["formatted_timestamp"]), styles["cell"]),
                    Paragraph(detail, styles["cell"]),
                ]
            )

        # Sütun genişlikleri sayfa genişliğinin ORANI olarak verilir (sabit mm
        # değil): kenar boşluğu ya da sayfa boyutu değişirse tablo kendiliğinden
        # uyar, sayfa dışına taşmaz.
        table = Table(
            table_data,
            # Oranlar deneyle sabitlendi: "Önem" sütunu en uzun etiketi
            # ("CRITICAL"), "Kural" sütunu en uzun kural kimliğini
            # ("SEC-DNS-TUNNEL-001") tek satırda taşıyacak kadar geniş olmalı --
            # aksi halde iki sütun da ortadan kırılıp okunaksız hale geliyordu.
            colWidths=[width * ratio for ratio in (0.11, 0.19, 0.19, 0.13, 0.38)],
            # repeatRows=1: tablo sayfa taştığında başlık satırı her yeni
            # sayfada yeniden basılır. Aksi halde ikinci sayfadan itibaren
            # hangi sütunun ne olduğu anlaşılamaz.
            repeatRows=1,
        )
        table.setStyle(self._data_table_style())
        story.append(table)
        return story

    def _threat_intel_section(
        self, payload: ExportPayload, styles: dict[str, ParagraphStyle], width: float
    ) -> list[Any]:
        """Threat Intelligence uzlaşı tablosu."""
        story: list[Any] = [Paragraph("5. Threat Intelligence", styles["heading"])]
        summaries = _prepare_threat_intel_for_template(payload.threat_intel)

        if not summaries:
            story.append(
                Paragraph(
                    "Threat Intelligence zenginleştirmesi çalıştırılmadı ya da "
                    "sorgulanacak genel (routable) IP bulunamadı. Bu, IP'lerin "
                    "temiz olduğu anlamına GELMEZ.",
                    styles["body"],
                )
            )
            return story

        header = [
            Paragraph("<b>IP</b>", styles["cell_bold"]),
            Paragraph("<b>Uzlaşı</b>", styles["cell_bold"]),
            Paragraph("<b>Değerlendirme</b>", styles["cell_bold"]),
            Paragraph("<b>Sağlayıcı Sonuçları</b>", styles["cell_bold"]),
        ]
        table_data: list[list[Any]] = [header]

        for summary in sorted(
            summaries, key=lambda s: (_CONSENSUS_ORDER.get(s.consensus_label, 99), s.ip)
        ):
            color = _SEVERITY_COLORS.get(summary.consensus_class, "#0f172a")
            provider_lines = "<br/>".join(
                f"{_esc(result.source)}: {self._verdict_text(result)}" for result in summary.results
            )
            table_data.append(
                [
                    Paragraph(_esc(summary.ip), styles["cell"]),
                    Paragraph(
                        f'<font color="{color}"><b>{_esc(summary.consensus_label)}</b></font>',
                        styles["cell"],
                    ),
                    Paragraph(_esc(summary.consensus_detail), styles["cell"]),
                    Paragraph(provider_lines, styles["cell"]),
                ]
            )

        table = Table(
            table_data,
            colWidths=[width * ratio for ratio in (0.18, 0.13, 0.345, 0.345)],
            repeatRows=1,
        )
        table.setStyle(self._data_table_style())
        story.append(table)
        story.append(Spacer(1, 5))
        story.append(
            Paragraph(
                "Ham skorlar sağlayıcıya özgüdür ve birbiriyle karşılaştırılamaz: "
                "VirusTotal = işaretleyen motor sayısı, AbuseIPDB = 0-100 güven "
                "skoru, OTX = pulse sayısı.",
                styles["muted"],
            )
        )
        return story

    @staticmethod
    def _verdict_text(result: Any) -> str:
        """Tek bir sağlayıcı sonucunu kısa metne çevirir (üç durumu koruyarak)."""
        if result.provider_error_code is not None:
            return f'<font color="#475569">yanıt yok ({_esc(result.provider_error_code.value)})</font>'
        if result.is_malicious is None:
            # None "temiz" DEĞİLDİR; sağlayıcı hüküm verememiştir.
            return '<font color="#475569">hüküm yok</font>'
        verdict = "ZARARLI" if result.is_malicious else "temiz"
        color = _SEVERITY_COLORS["CRITICAL"] if result.is_malicious else _SEVERITY_COLORS["LOW"]
        score = "" if result.raw_score is None else f" (ham skor: {_esc(result.raw_score)})"
        return f'<font color="{color}">{verdict}</font>{score}'

    def _charts_section(
        self, payload: ExportPayload, styles: dict[str, ParagraphStyle], width: float
    ) -> list[Any]:
        """Grafikler; belgenin sonunda ek olarak yer alır.

        Sonda olmalarının sebebi: bulgular ve risk özeti kararı belirleyen
        bilgidir, grafikler ise onu destekleyen görsel kanıttır. Basılı bir
        raporu okuyan kişi ilk sayfada sonucu görmelidir.
        """
        sections = build_chart_sections(payload.statistics, ChartBuilder())
        if not sections:
            return []

        story: list[Any] = [PageBreak(), Paragraph("EK: Trafik Grafikleri", styles["heading"])]
        for section in sections:
            story.append(
                KeepTogether(
                    [
                        Paragraph(f"<b>{_esc(section.title)}</b>", styles["body"]),
                        Paragraph(_esc(section.description), styles["muted"]),
                        Spacer(1, 4),
                        _scaled_image(base64.b64decode(section.image), width),
                        Spacer(1, 10),
                    ]
                )
            )
        return story

    # ------------------------------------------------------------------
    # Ortak tablo yardımcıları
    # ------------------------------------------------------------------
    @staticmethod
    def _key_value_table(
        rows: list[tuple[str, str]],
        styles: dict[str, ParagraphStyle],
        width: float,
        pre_escaped: bool = False,
    ) -> Table:
        """İki sütunlu "alan / değer" tablosu üretir.

        Args:
            pre_escaped: Değerler zaten kaçırılmış ve <font> gibi işaretleme
                içeriyorsa True. Varsayılan False'ta değer kaçırılır -- dış
                kaynaklı metinlerin işaretleme olarak yorumlanmaması için.
        """
        table = Table(
            [
                [
                    Paragraph(f"<b>{_esc(label)}</b>", styles["cell"]),
                    Paragraph(value if pre_escaped else _esc(value), styles["cell"]),
                ]
                for label, value in rows
            ],
            colWidths=[45 * mm, width - 45 * mm],
        )
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3.5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
                ]
            )
        )
        return table

    @staticmethod
    def _data_table_style() -> TableStyle:
        """Bulgu/TI tabloları için ortak stil (başlık şeridi + zebra satırlar)."""
        return TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ]
        )


def _scaled_image(png_bytes: bytes, max_width: float) -> Image:
    """PNG baytlarını sayfa genişliğine oranını koruyarak ölçeklenmiş Image'a çevirir.

    Ölçü için ayrı bir tampon kullanılır: ImageReader tamponu sonuna kadar
    okur, aynı tampon Image'a verilirse boş görünür.
    """
    natural_width, natural_height = ImageReader(io.BytesIO(png_bytes)).getSize()
    scale = max_width / natural_width
    height = natural_height * scale

    max_height = _MAX_CHART_HEIGHT_MM * mm
    if height > max_height:
        scale *= max_height / height

    return Image(
        io.BytesIO(png_bytes),
        width=natural_width * scale,
        height=natural_height * scale,
        # lazy=0: görsel hemen belleğe okunur. Varsayılan gecikmeli okumada
        # ReportLab dosyayı build() sırasında yeniden açmaya çalışır; BytesIO
        # tamponunda bu başarısız olur.
        lazy=0,
    )


def _numbered_canvas_factory(font_name: str) -> type:
    """"Sayfa X / Y" altbilgisi basan bir Canvas sınıfı üretir.

    Toplam sayfa sayısı ancak belge tamamen dizildikten sonra bilinebilir; bu
    yüzden sayfalar önce bellekte biriktirilir, sayfa sayısı kesinleştikten
    sonra altbilgi basılarak yazılır (ReportLab'in bilinen iki geçişli deseni).

    Sınıf bir fabrika içinde tanımlanır çünkü `pdf_canvas` yalnızca reportlab
    kuruluysa mevcuttur; modül seviyesinde tanımlansaydı, reportlab olmayan bir
    ortamda bu dosya hiç import edilemez ve JSON/CSV export'ları da çalışmazdı.
    """

    class _NumberedCanvas(pdf_canvas.Canvas):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._saved_pages: list[dict[str, Any]] = []

        def showPage(self) -> None:  # noqa: N802 - ReportLab API adı
            self._saved_pages.append(dict(self.__dict__))
            self._startPage()

        def save(self) -> None:
            total_pages = len(self._saved_pages)
            for state in self._saved_pages:
                self.__dict__.update(state)
                self._draw_footer(total_pages)
                super().showPage()
            super().save()

        def _draw_footer(self, total_pages: int) -> None:
            self.setFont(font_name, 7.5)
            self.setFillColorRGB(0.42, 0.45, 0.50)
            self.drawRightString(
                A4[0] - _PAGE_MARGIN * mm,
                10 * mm,
                f"Sayfa {self._pageNumber} / {total_pages}",
            )
            self.drawString(
                _PAGE_MARGIN * mm,
                10 * mm,
                "Automated PCAP Forensic Analysis Tool — otomatik üretilmiş adli belge",
            )

    return _NumberedCanvas
