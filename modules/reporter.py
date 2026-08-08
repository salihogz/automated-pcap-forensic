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
import hashlib
import io
import logging
import math
import sys
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import matplotlib

matplotlib.use("Agg")  # GUI'siz ortamlarda (sunucu/CI) render için zorunlu.

import matplotlib.pyplot as plt
from jinja2 import Environment, FileSystemLoader, select_autoescape
from jinja2.exceptions import TemplateError, UndefinedError

import config
from modules.models import GeneralStatistics, ThreatFinding, ThreatSeverity
from modules.output_paths import resolve_output_dir
from modules.threat_intel import NormalizedIOCResult

logger = logging.getLogger(__name__)

# GÜVENLİK: matplotlib, etiket metinlerindeki "$...$" çiftlerini varsayılan
# olarak TeX matematik ifadesi (mathtext) sayıp ayrıştırır. Grafik etiketleri
# capture'dan gelen -- yani SALDIRGANIN KONTROLÜNDEKİ -- hostname'leri içerir
# (bkz. ip_hostname_map; DNS yanıtlarından türetilir). Ayrıştırılamayan bir
# ifade ValueError fırlatır ve bu istisna ChartBuilder ile main() arasında
# hiçbir yerde yakalanmaz: RAPOR HİÇ ÜRETİLEMEZ.
#
# Yani hedef ağda "a$$b.example.com" gibi bir alan adının çözümlenmesini
# sağlayabilen bir saldırgan, kendi trafiğinin adli raporunun hiç
# oluşturulmamasını sağlayabiliyordu -- delili yok etmeye yakın bir etki.
# Doğrulanan payload'lar: "a$$b.com", "a$\frac{1}$b.com", "a$\nonexistentcmd$b.com".
#
# `text.parse_math=False` mathtext ayrıştırmasını tümüyle kapatır; "$" düz bir
# karakter olarak basılır. Etiketleri tek tek kaçırmak yerine bunun seçilmesi
# bilinçlidir: sonradan eklenen her grafik de kendiliğinden korunur.
#
# `matplotlib.use()`'un aksine bu ayarın import'lardan ÖNCE olması gerekmez --
# rcParams render anında okunur -- bu yüzden import bloğunun altında duruyor
# (E402: import'lar dosyanın başında kalsın).
matplotlib.rcParams["text.parse_math"] = False

_TEMPLATE_DIR: Final[Path] = Path(__file__).resolve().parent.parent / "templates"
_TEMPLATE_NAME: Final[str] = "report.html.j2"
# Sürüm tek kaynaktan (config) okunur; rapordaki "Araç Sürümü" alanı adli bir
# belgenin parçası olduğu için bu değerin başka yerlerdeki sürümlerle
# çelişmemesi gerekir.
_TOOL_VERSION: Final[str] = config.TOOL_VERSION

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
#
# Sabitlenmiş sınır değerleri (testlerle korunuyor, API sözleşmesi sayılır):
# 0 -> TEMİZ, 4 -> DÜŞÜK, 5 -> ORTA, 14 -> ORTA, 15 -> YÜKSEK, 29 -> YÜKSEK,
# 30 -> KRİTİK.
#
# DÜŞÜK eşiği 4 DEĞİL 1'dir. Daha önce 4'tü ve bu, adli bir araçta kabul
# edilemez bir yanlış sonuç üretiyordu: 1, 2 veya 3 puanlık skorlar (yani
# 1-3 adet LOW bulgu) hiçbir eşiği karşılamadığı için "TEMİZ" kovasına
# düşüyordu. Rapor, bulgu tablosunda gerçek bulgular listelerken en üstte
# "Risk Seviyesi: TEMİZ" yazıyordu. Bir DFIR raporunda hatanın bu yönü
# (var olan bulguyu yok saymak) en tehlikeli olanıdır. 1'e çekmek, yukarıda
# sabitlenmiş sınırların hiçbirini değiştirmez -- 4 hâlâ DÜŞÜK, 5 hâlâ ORTA --
# yalnızca 1-3 aralığındaki boşluğu kapatır.
_RISK_THRESHOLDS: Final[tuple[tuple[int, str, str], ...]] = (
    (0, "TEMİZ", "clean"),
    (1, "DÜŞÜK", "low"),
    (5, "ORTA", "medium"),
    (15, "YÜKSEK", "high"),
    (30, "KRİTİK", "critical"),
)

# `risk_score` SINIRSIZ bir ağırlıklı toplamdır (7 HIGH = 105, 20 HIGH = 300);
# eşik tablosu bu ham değere göre kalibre edildiğinden ham değer asla
# ölçeklenmemeli veya kırpılmamalıdır. İlerleme çubuğunun genişliği ise
# `width: N%` olduğundan 0-100 aralığında bir değere ihtiyaç duyar.
_RISK_SCORE_DISPLAY_MAX: Final[int] = 100

# Çubuk, KRİTİK bandında eşiğin bu KATINA ulaşınca tamamen dolar
# (30 * 4 = 120 puan). Sınırsız bir skoru sonlu bir çubuğa sığdırmak için bir
# doyma noktası gerekir; 4 kat, "birkaç kritik bulgu" ile "capture baştan sona
# saldırı" durumlarını ayırt edecek kadar geniştir.
_CRITICAL_BAR_SATURATION_FACTOR: Final[int] = 4


def _compute_risk_bar_position(risk_score: int) -> int:
    """Ham risk skorunu ilerleme çubuğunun doluluk yüzdesine çevirir.

    NEDEN DÜZ `min(skor, 100)` DEĞİL: Çubuk eskiden skoru doğrudan yüzde
    olarak kullanıyordu ve bu, çubuğun RİSK SEVİYESİ ETİKETİYLE ÇELİŞMESİNE
    yol açıyordu. Tek bir CRITICAL bulgu 30 puan eder; rapor "Risk Seviyesi:
    KRİTİK" yazarken hemen altındaki çubuk %30 dolu -- yani gözle "düşük
    risk" -- görünüyordu. Ters uçta ise 20 HIGH (300 puan) ile 100 CRITICAL
    (3000 puan) çubukta ayırt edilemiyordu, ikisi de %100'e kırpılıyordu.
    Çubuk, adı "yüzde" olan ama hiçbir tanımlı büyüklüğü ölçmeyen bir
    göstergeydi.

    Bunun yerine çubuk artık SEVİYE BANDINI gösterir: TEMİZ dışındaki dört
    bandın (DÜŞÜK/ORTA/YÜKSEK/KRİTİK) her biri çubuğun %25'ini kaplar, band
    içinde skorla orantılı olarak ilerlenir. Böylece KRİTİK daima >= %75
    dolu görünür ve çubuk ile etiket asla çelişmez. KRİTİK bandı sınırsız
    olduğu için eşiğin `_CRITICAL_BAR_SATURATION_FACTOR` katında doyar.

    Ham `risk_score` bu dönüşümden ETKİLENMEZ; raporda olduğu gibi, sayı
    olarak gösterilmeye devam eder (kanıt kaybı olmaz).
    """
    if risk_score <= 0:
        return 0

    thresholds = [threshold for threshold, _label, _css in _RISK_THRESHOLDS]
    band_count = len(thresholds) - 1  # TEMİZ bandı çubukta yer kaplamaz
    band_width = _RISK_SCORE_DISPLAY_MAX / band_count

    # Skorun içine düştüğü bandı bul (1..band_count).
    band_index = 1
    for i in range(1, len(thresholds)):
        if risk_score >= thresholds[i]:
            band_index = i

    band_start = thresholds[band_index]
    if band_index < len(thresholds) - 1:
        band_end = thresholds[band_index + 1]
    else:
        # En üst (KRİTİK) band sınırsız; yapay bir doyma noktası kullanılır.
        band_end = band_start * _CRITICAL_BAR_SATURATION_FACTOR

    span = band_end - band_start
    progress = (risk_score - band_start) / span if span > 0 else 1.0
    progress = min(max(progress, 0.0), 1.0)

    position = (band_index - 1) * band_width + progress * band_width
    # Sıfırdan büyük her skor gözle görülür bir dolgu üretmeli; aksi halde
    # "DÜŞÜK" seviyesi tamamen boş bir çubukla, yani "TEMİZ" ile aynı
    # görünürdü.
    return max(1, min(round(position), _RISK_SCORE_DISPLAY_MAX))

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


# Dosya sabit boyutlu parçalar halinde okunur ki büyük capture dosyaları
# (GB mertebesinde) hash hesabı için tek seferde belleğe alınmasın —
# modül genelindeki streaming/memory-friendly ilkeyle tutarlı.
_SHA256_CHUNK_SIZE: Final[int] = 1024 * 1024  # 1 MB


def _compute_sha256(file_path: Path) -> str | None:
    """Kaynak PCAP dosyasının SHA256 özetini hesaplar (chain-of-custody).

    Adli bilişimde delil dosyasının bütünlüğünün (analiz sırasında hiç
    değişmediğinin) kanıtlanması standart bir gerekliliktir; rapor bu
    özeti "Chain of Custody" alanında gösterir. Hesaplama başarısız
    olursa (örn. dosya bu adımdan önce taşınmış/silinmişse ya da okuma
    izni yoksa) rapor üretimi bu yüzden durmaz — Fail Soft: sha256 alanı
    None kalır, durum loglanır (bkz. `_format_timestamp_value` ile aynı
    desen: sunum katmanındaki tek bir eksik alan, tüm rapor üretimini
    engellememelidir).
    """
    try:
        digest = hashlib.sha256()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(_SHA256_CHUNK_SIZE), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        logger.warning("Kaynak dosyanın SHA256 özeti hesaplanamadı: %s", exc)
        return None


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
    # İlerleme çubuğunun doluluk yüzdesi (0-100). Skorun kendisi DEĞİL,
    # skorun içine düştüğü risk BANDININ çubuktaki konumudur — bkz.
    # _compute_risk_bar_position. Yalnızca SUNUM içindir; karşılaştırma veya
    # eşik mantığında asla kullanılmamalıdır (onun için risk_score vardır).
    # Varsayılan değeri kasıtlı olarak yoktur: sessizce 0 genişlikli bir
    # çubuk üretmek yerine, eksik bırakılırsa kurulum anında hata versin.
    risk_score_normalized: int


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
        risk_score_normalized=_compute_risk_bar_position(risk_score),
    )


# Bulgu (evidence) sözlüklerinde epoch/unix zaman damgası taşıdığı bilinen
# anahtarlar. Bu anahtarların değerleri, rapora yazılmadan önce insan
# tarafından okunabilir bir tarihe çevrilir. Yeni bir tespit kuralı evidence
# içine zaman damgası koyarsa, anahtarını buraya eklemesi yeterlidir.
#
# NOT: `first_seen_epoch`/`last_seen_epoch`, threat_detector.py'deki
# kuralların (port/syn scan, SYN flood, ICMP flood, failed-TCP, DNS tunneling,
# exfiltration) fiilen ürettiği anahtarlardır. `ilk_gorulme`/`son_gorulme`
# ise yalnızca `_group_recurring_findings()`'in tekrarlanan bulguları
# birleştirirken ürettiği anahtarlardır (bkz. o fonksiyon).
_EVIDENCE_TIME_KEYS: Final[frozenset[str]] = frozenset(
    {"first_seen_epoch", "last_seen_epoch", "ilk_gorulme", "son_gorulme"}
)

_EVIDENCE_LABELS: Final[dict[str, str]] = {
    "distinct_port_count": "Farklı Port Sayısı",
    "time_window_seconds": "Zaman Penceresi (sn)",
    "first_seen_epoch": "İlk Görülme",
    "last_seen_epoch": "Son Görülme",
    "sampled_ports": "Örneklenen Portlar",
    "total_packets_in_window": "Pencere İçindeki Paket Sayısı",
    "transport_protocols": "Taşıma Protokolleri",
    "packet_count": "Paket Sayısı",
    "failed_attempt_count": "Başarısız Deneme Sayısı",
    "sampled_target_ports": "Örneklenen Hedef Portlar",
    "base_domain": "Temel Alan Adı",
    "query_count": "Sorgu Sayısı",
    "suspicious_qtype_count": "Şüpheli Kayıt Tipi Sayısı",
    "sampled_queries": "Örneklenen Sorgular",
    "total_bytes": "Toplam Byte",
    "total_megabytes": "Toplam MB",
    "threshold_bytes": "Eşik (Byte)",
    "total_long_domains": "Uzun Alan Adı Sayısı",
    "total_dga_domains": "DGA Şüpheli Alan Adı Sayısı",
    "domains": "Alan Adları",
    "tekrar_sayisi": "Tekrar Sayısı",
    "ilk_gorulme": "İlk Görülme",
    "son_gorulme": "Son Görülme",
    # `domains` listesindeki kayıtların içindeki alanlar (bkz.
    # _format_evidence_record).
    "domain": "Alan Adı",
    "length": "Uzunluk",
    "label": "Etiket",
    "entropy": "Entropi",
    "src_ip": "Kaynak IP",
    "timestamp": "Zaman",
}


def _format_evidence_record(record: dict[str, Any]) -> str:
    """Kanıt listesindeki tek bir kaydı ("domains" öğesi) okunabilir metne çevirir."""
    parts = []
    for key, value in record.items():
        label = _EVIDENCE_LABELS.get(key, key)
        rendered = _format_timestamp_value(value) if key == "timestamp" else value
        parts.append(f"{label}: {rendered}")
    return " · ".join(parts)


def _format_evidence_value(value: Any) -> Any:
    """Kanıt değerini şablona hazır, insan tarafından okunabilir biçime getirir.

    Neden gerekli: kanıt sözlüğündeki bazı değerler LİSTEDİR (`domains`,
    `sampled_ports`, `sampled_queries`, `transport_protocols`). Şablon bunları
    doğrudan `{{ val }}` ile bastığında Jinja, Python'un `repr()` çıktısını
    yazıyordu; yani adli raporun "Kanıt" sütununda şuna benzer bir blok
    görünüyordu:

        [{'domain': 'j7r8af...example.com', 'length': 72, 'src_ip':
        '10.0.0.66', 'timestamp': 1772355840.0}, {'domain': ...

    Süslü parantezler, tırnaklar ve ham epoch sayıları raporu okuyan analist
    için gürültüdür; üstelik SEC-DGA-001/SEC-LONG-DOMAIN-001 bulgularında bu
    tek hücre yüzlerce satıra çıkıp tabloyu ezip geçiyordu. Burada listeler
    satır satır, sözlükler "Etiket: değer" çiftleri olarak yazılır; zaman
    damgaları da diğer kanıt alanlarıyla aynı biçime çevrilir.

    Satırlar "\\n" ile birleştirilir; şablondaki `.evidence-val` sınıfı
    `white-space: pre-line` ile bunları görsel satır sonlarına dönüştürür
    (HTML üretmek yerine düz metin döndürmek autoescape'i bozmamak için
    bilinçli bir tercihtir).
    """
    if isinstance(value, (list, tuple)):
        if not value:
            return "-"
        if all(isinstance(item, dict) for item in value):
            return "\n".join(_format_evidence_record(item) for item in value)
        return "\n".join(str(item) for item in value)
    return value


def _format_timestamp_value(value: Any) -> str:
    """Epoch (float/int) veya datetime değerini 'YYYY-MM-DD HH:MM:SS UTC' biçimine çevirir.

    Ayrıştırılamayan/None değerler için ham HTML'e çirkin bir epoch float
    yazmak yerine güvenli bir varsayılan döner (Fail Soft: rapor üretimi
    tek bir bozuk zaman damgası yüzünden durmamalıdır).
    """
    if value is None:
        return "-"
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    # Epoch 0, parser'ın OKUNAMAYAN zaman damgası için verdiği sentinel'dir
    # (bkz. parser._parse_single_packet). Olduğu gibi biçimlendirilirse rapor
    # "1970-01-01 00:00:00 UTC" yazar ve capture'da gerçekten o tarihte bir
    # olay varmış izlenimi verir -- adli bir belgede uydurma bir tarih,
    # eksik bir alandan daha zararlıdır. CSV export'u aynı değeri zaten boş
    # hücreye çeviriyordu (bkz. csv_exporter._epoch_to_iso); bu kontrol iki
    # çıktının aynı şeyi söylemesini sağlar.
    if isinstance(value, (int, float)) and not value:
        return "-"
    try:
        return datetime.fromtimestamp(float(value), tz=UTC).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except (TypeError, ValueError, OSError):
        return str(value)


def _with_hostname(ip_or_endpoint: str | None, hostname_map: dict[str, str]) -> str | None:
    """Bir IP (veya 'IP:port' biçimindeki endpoint) değerini, DNS'te
    görülmüş bir hostname varsa "IP (hostname)" biçiminde zenginleştirir.

    Önce değerin TAMAMI aranır, ancak sonra ':' öncesindeki parçaya bakılır.
    Bu sıra IPv6 için zorunludur: bir IPv6 adresi (`2606:4700::1111`) baştan
    sona iki nokta içerir, dolayısıyla yalnızca ':' öncesine bakan eski
    davranış anahtarı `2606` sanıyor ve HİÇBİR IPv6 adresi için hostname
    bulamıyordu -- DNS'in AAAA yanıtından hostname öğrenilmiş olsa bile.
    Sonuç, aynı raporda IPv4 hostlarının "IP (hostname)", IPv6 hostlarının
    ise yalnızca "IP" olarak görünmesiydi.

    ':' öncesine düşülmesi, port taşıyan endpoint biçimi ('1.2.3.4:443')
    içindir; port bilgisi görüntüde korunur.
    """
    if not ip_or_endpoint:
        return ip_or_endpoint

    hostname = hostname_map.get(ip_or_endpoint) or hostname_map.get(
        ip_or_endpoint.split(":", 1)[0]
    )
    if not hostname:
        return ip_or_endpoint
    return f"{ip_or_endpoint} ({hostname})"


def _format_bytes(num_bytes: float) -> str:
    """Byte cinsinden bir değeri KB/MB/GB gibi okunabilir birime çevirir.

    Döngü "TB" biriminde her koşulda döner; sondaki `raise` yalnızca bu
    değişmezi belgeler, çalışma zamanında erişilmez.
    """
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:,.2f} {unit}" if unit != "B" else f"{int(value):,} B"
        value /= 1024
    raise AssertionError("ulaşılamaz: döngü 'TB' biriminde her zaman döner")


def _group_recurring_findings(findings: Sequence[ThreatFinding]) -> list[ThreatFinding]:
    """Aynı (rule_id, source, destination) üçlüsü için tekrar eden bulguları
    rapor GÖRÜNÜMÜNDE tek satıra indirger.

    Neden gerekli: Kayan pencere tabanlı kurallar (Port Scan ve benzerleri),
    bir saldırı/tarama devam ettiği sürece art arda bir çok ayrı ThreatFinding
    üretir (her biri kendi zaman penceresinin geçerli kanıtıdır). Bu, adli
    açıdan doğrudur ama aynı satırın onlarca kez tekrarlandığı bir raporu
    analist için okunaksız hale getirir.

    Saf fonksiyon: girdiyi değiştirmez, `dataclasses.replace` ile SADECE
    description/evidence alanlarını bu bulgu grubunu özetleyecek şekilde
    zenginleştirilmiş YENİ ThreatFinding nesneleri üretir; hiçbir orijinal
    alan icat edilmez veya silinmez (chain of custody korunur).

    ÖNEMLİ: Bu fonksiyonun çıktısı SADECE raporun "Tehdit Bulguları" tablosu
    için kullanılmalıdır. Risk skoru (`compute_risk_summary`) her zaman
    orijinal, gruplanmamış bulgu listesiyle hesaplanmalıdır; aksi halde 8
    ayrı tespit tek bir CRITICAL bulgu gibi görünüp risk skorunu yanlışlıkla
    düşürür.
    """
    groups: dict[tuple[str, str, str | None], list[ThreatFinding]] = defaultdict(list)
    order: list[tuple[str, str, str | None]] = []

    for finding in findings:
        key = (finding.rule_id, finding.source, finding.destination)
        if key not in groups:
            order.append(key)
        groups[key].append(finding)

    result: list[ThreatFinding] = []
    for key in order:
        group = groups[key]
        if len(group) == 1:
            result.append(group[0])
            continue

        group_sorted = sorted(group, key=lambda f: f.timestamp or 0)
        representative = group_sorted[-1]
        first_seen = group_sorted[0].timestamp
        last_seen = group_sorted[-1].timestamp
        occurrence_count = len(group_sorted)

        merged_evidence = dict(representative.evidence)
        merged_evidence["tekrar_sayisi"] = occurrence_count
        merged_evidence["ilk_gorulme"] = first_seen
        merged_evidence["son_gorulme"] = last_seen

        merged_description = (
            f"{representative.description} Bu davranış aynı kaynak-hedef çifti "
            f"için {occurrence_count} ayrı zaman penceresinde tekrar tespit edildi "
            f"(ilk: {_format_timestamp_value(first_seen)}, "
            f"son: {_format_timestamp_value(last_seen)})."
        )

        result.append(
            replace(representative, description=merged_description, evidence=merged_evidence)
        )

    return result


def _prepare_statistics_for_template(stats: GeneralStatistics) -> dict[str, Any]:
    """GeneralStatistics'i şablonun beklediği türetilmiş alanlarla zenginleştirir."""
    net = stats.network_protocol_distribution
    trans = stats.transport_protocol_distribution
    app = stats.application_protocol_distribution

    top_ip = stats.top_source_ips[0][0] if stats.top_source_ips else None
    top_ip_display = _with_hostname(top_ip, stats.ip_hostname_map) if top_ip else None

    return {
        **stats.to_dict(),
        "total_bytes_formatted": _format_bytes(stats.total_bytes),
        "start_time_formatted": _format_timestamp_value(stats.first_packet_time),
        "end_time_formatted": _format_timestamp_value(stats.last_packet_time),
        "duration_formatted": f"{stats.capture_duration:.2f}s",
        "top_source_ip": top_ip_display,
        "ipv4_count": net.get("IPv4", 0),
        "ipv6_count": net.get("IPv6", 0),
        "tcp_count": trans.get("TCP", 0),
        "udp_count": trans.get("UDP", 0),
        "http_count": app.get("HTTP", 0),
        "dns_count": app.get("DNS", 0),
        # HTTPS trafiği iki farklı taşıma üzerinde koşar: TLS (TCP) ve QUIC
        # (UDP, HTTP/3). Kart yalnızca TLS'i gösterip "(HTTPS)" diye
        # etiketlendiğinde, QUIC'in ağırlıklı olduğu modern trafikte HTTPS
        # hacmi olduğundan az görünüyordu — ölçülen bir capture'da 233.136 TLS
        # yanında 3.353 QUIC paketi kartta hiç yer almıyordu.
        "tls_count": app.get("TLS", 0),
        "quic_count": app.get("QUIC", 0),
    }


@dataclass(frozen=True, slots=True)
class ThreatIntelSummary:
    """Bir IP için sağlayıcı sonuçlarının rapora hazır özeti."""

    ip: str
    results: list[NormalizedIOCResult]
    total_providers: int
    answered_providers: int
    malicious_providers: int
    consensus_label: str
    consensus_class: str
    consensus_detail: str


def _prepare_threat_intel_for_template(
    threat_intel: dict[str, list[NormalizedIOCResult]],
) -> list[ThreatIntelSummary]:
    """IP başına sağlayıcı sonuçlarını, "cevap verememe"yi "temiz" saymayan
    bir uzlaşı (consensus) özetine dönüştürür.

    NEDEN PYTHON'DA, ŞABLONDA DEĞİL: Bu mantık daha önce şablonun içinde
    `selectattr` zincirleriyle yapılıyordu ve sessizce YANLIŞ bir sonuç
    üretiyordu:

        {% elif clean_count > 0 %} CONSENSUS: CLEAN

    Üç sağlayıcıdan ikisi zaman aşımına uğrayıp yalnızca biri "temiz" dediğinde
    bu dal çalışıyor ve rapor "0 / 3 sağlayıcı zararlı dedi — CONSENSUS: CLEAN"
    yazıyordu. Hâlbuki uzlaşı diye bir şey yoktu: üç sağlayıcının ikisi HİÇ OY
    KULLANAMAMIŞTI. `NormalizedIOCResult.is_malicious` üç durumludur ve `None`
    "sağlayıcı hüküm veremedi" demektir — asla "temiz" ile karıştırılmamalıdır
    (bkz. threat_intel.py). Bir IOC'yi yanlışlıkla temiz göstermek, adli bir
    raporda yapılabilecek en zararlı hatadır; payda da artık toplam sağlayıcı
    değil, YANIT VEREN sağlayıcı sayısıdır.
    """
    summaries: list[ThreatIntelSummary] = []

    for ip, results in threat_intel.items():
        total = len(results)
        answered = [r for r in results if r.is_malicious is not None]
        malicious = [r for r in answered if r.is_malicious is True]
        unanswered = total - len(answered)
        # Eşiği aşmadığı için "zararlı" denmeyen, ama sıfır da olmayan skorlar.
        # Bkz. aşağıdaki "ŞÜPHELİ" dalı.
        sub_threshold = [
            r
            for r in answered
            if r.is_malicious is False and r.raw_score is not None and r.raw_score > 0
        ]

        if not answered:
            label, css = "VERİ YOK", "INFO"
            detail = f"Hiçbir sağlayıcı hüküm veremedi ({total} sağlayıcı denendi)."
        elif len(malicious) == len(answered):
            label, css = "ZARARLI", "CRITICAL"
            detail = f"Yanıt veren {len(answered)} sağlayıcının tamamı zararlı dedi."
        elif malicious:
            label, css = "ÇELİŞKİLİ", "HIGH"
            detail = f"Yanıt veren {len(answered)} sağlayıcıdan {len(malicious)} tanesi zararlı dedi."
        elif sub_threshold:
            # Hiçbir sağlayıcı eşiği aşmadı ama en az biri SIFIR OLMAYAN bir
            # sinyal döndürdü (ör. VirusTotal'de 2 motor, AbuseIPDB'de 24).
            # Bunu "TEMİZ" yazmak, "3 sağlayıcının tamamı temiz dedi" gibi
            # veriyi AŞAN bir iddia olurdu: hiçbiri temiz demedi, hepsi zayıf
            # bir olumlu sinyal verdi. Eşikler (config.py) yanlış pozitifleri
            # elemek için var, kanıtı yok saymak için değil.
            label, css = "ŞÜPHELİ", "MEDIUM"
            signals = ", ".join(
                f"{r.source}: {r.raw_score}"
                for r in answered
                if r.raw_score is not None and r.raw_score > 0
            )
            detail = (
                f"Hiçbir sağlayıcı zararlı hükmü verecek eşiği aşmadı, ancak sıfır "
                f"olmayan sinyal var ({signals}). Eşik altı kaldığı için hüküm "
                f"verilmedi; ham skorlar aşağıdadır."
            )
        elif unanswered:
            label, css = "KISMİ TEMİZ", "MEDIUM"
            detail = (
                f"Yanıt veren {len(answered)} sağlayıcı temiz dedi, ancak {unanswered} "
                f"sağlayıcı hüküm veremedi — sonuç eksiktir."
            )
        else:
            label, css = "TEMİZ", "LOW"
            detail = f"{total} sağlayıcının tamamı yanıt verdi ve temiz dedi."

        summaries.append(
            ThreatIntelSummary(
                ip=ip,
                results=list(results),
                total_providers=total,
                answered_providers=len(answered),
                malicious_providers=len(malicious),
                consensus_label=label,
                consensus_class=css,
                consensus_detail=detail,
            )
        )

    return summaries


def _prepare_findings_for_template(
    findings: Sequence[ThreatFinding], hostname_map: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    """ThreatFinding nesnelerini şablonun (report.html.j2) beklediği, insan
    tarafından okunabilir sunum alanlarıyla (formatted_timestamp, formatlanmış
    kanıt zaman damgaları, hostname zenginleştirmeli source/destination)
    zenginleştirilmiş salt-okunur dict listesine dönüştürür.

    Ham ThreatFinding/dataclass nesneleri bu dönüşümden ETKİLENMEZ; bu
    fonksiyon yalnızca View katmanı için ayrı bir temsil üretir (Presentation
    != Domain Model ayrımı).
    """
    hostname_map = hostname_map or {}
    rows: list[dict[str, Any]] = []
    for finding in findings:
        evidence = dict(finding.evidence)
        for key in _EVIDENCE_TIME_KEYS:
            if key in evidence:
                evidence[key] = _format_timestamp_value(evidence[key])

        evidence_display = [
            (_EVIDENCE_LABELS.get(k, k), _format_evidence_value(v))
            for k, v in evidence.items()
        ]

        rows.append(
            {
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity,
                "description": finding.description,
                "evidence": evidence,
                "evidence_display": evidence_display,
                "source": finding.source,
                "destination": finding.destination,
                "source_display": _with_hostname(finding.source, hostname_map),
                "destination_display": _with_hostname(finding.destination, hostname_map),
                "timestamp": finding.timestamp,
                "formatted_timestamp": _format_timestamp_value(finding.timestamp),
            }
        )
    return rows


class ChartBuilder:
    """İstatistik verilerinden base64 kodlu PNG grafikler ve detay tabloları inşa eder.

    Bu sınıf bilinçli olarak Jinja2'den, dosya sisteminden ve Reporter'ın
    geri kalanından habersizdir (sadece dict/list -> (str, list[TableRow])
    dönüşümü yapar). Bu izolasyon, matplotlib çağrılarını mock'lamadan gerçek
    girdi/çıktı üzerinden birim test etmeyi mümkün kılabilir.
    """

    _FIGSIZE: Final[tuple[float, float]] = (8.0, 4.2)
    _DPI: Final[int] = 110

    # Bu orandan (en büyük / en küçük protokol) itibaren x ekseni logaritmik
    # ölçeğe geçer. Bkz. protocol_distribution_chart.
    _LOG_SCALE_RATIO_THRESHOLD: Final[float] = 100.0

    def protocol_distribution_chart(
        self, distribution: dict[str, int]
    ) -> tuple[str | None, list[TableRow]]:
        """Protokol dağılımı için yatay bar grafiği ve analist veri tablosu üretir.

        NEDEN PASTA DEĞİL: Gerçek trafikte protokol dağılımı neredeyse her
        zaman tek bir protokolün ezici üstünlüğüyle gelir. Ölçülen bir
        capture'da 233.136 TLS paketine karşılık 328 DNS ve 26 NTP paketi
        vardı; yani oran 9000:1. Pasta grafiğinde bu, %98,4'lük tek bir
        daire ve gözle görülemeyen -bir çizgiden ince- dilimler demekti;
        legend "NTP (%0.0)" yazıyordu. Oysa adli analizde ilginç olan
        genellikle ezici çoğunluk DEĞİL, tam da o uzun kuyruktur: 26 paketlik
        beklenmedik bir protokol, 233 bin paketlik sıradan HTTPS trafiğinden
        çok daha anlamlıdır.

        Yatay bar + gerektiğinde LOGARİTMİK x ekseni bu kuyruğu görünür kılar.
        Ölçek koşulludur: en büyük/en küçük oranı
        `_LOG_SCALE_RATIO_THRESHOLD`'un altındaysa doğrusal ölçek daha dürüst
        ve okunaklıdır. Hangi ölçeğin kullanıldığı eksen etiketine yazılır ki
        logaritmik bir grafik yanlışlıkla doğrusal okunmasın; ayrıca her
        barın ucuna GERÇEK sayı ve yüzde yazılır, dolayısıyla görsel oran
        yanıltsa bile veri tam olarak okunabilir.
        """
        if not distribution:
            return None, []

        items = sorted(distribution.items(), key=lambda kv: kv[1], reverse=True)
        total = sum(value for _, value in items)

        # barh en büyüğü en üstte göstersin diye ters çeviriyoruz.
        labels = [label for label, _ in reversed(items)]
        values = [value for _, value in reversed(items)]

        smallest = min(v for v in values if v > 0) if any(values) else 1
        use_log = max(values) / smallest >= self._LOG_SCALE_RATIO_THRESHOLD

        fig, ax = plt.subplots(figsize=self._FIGSIZE, dpi=self._DPI)
        bars = ax.barh(labels, values, color="#2563eb")
        ax.set_title("Protokol Dağılımı")

        if use_log:
            ax.set_xscale("log")
            # Log ekseninde bar tabanı 0 olamaz; sol sınır 1 paketin biraz
            # altına çekilir ki en küçük protokolün barı da görünür kalsın.
            ax.set_xlim(left=0.7, right=max(values) * 3)
            ax.set_xlabel("Paket Sayısı (logaritmik ölçek)")
        else:
            ax.set_xlim(right=max(values) * 1.25)
            ax.set_xlabel("Paket Sayısı")

        for bar, value in zip(bars, values, strict=True):
            ax.annotate(
                f"{value:,} ({value / total:.1%})",
                xy=(bar.get_width(), bar.get_y() + bar.get_height() / 2),
                xytext=(4, 0),
                textcoords="offset points",
                va="center",
                fontsize=8,
            )

        fig.tight_layout()

        table_data = [
            TableRow(label=label, value=f"{value:,} ({value / total:.1%})")
            for label, value in items
        ]
        return self._to_base64(fig), table_data

    # Katman bazlı grafikte her katmanın rengi. Sıra aynı zamanda grafikteki
    # yukarıdan aşağıya sırayı belirler (ağ -> taşıma -> uygulama, yani
    # paketin katman yığınındaki sırayla).
    _PROTOCOL_LAYERS: Final[tuple[tuple[str, str], ...]] = (
        ("Ağ", "#0ea5e9"),
        ("Taşıma", "#2563eb"),
        ("Uygulama", "#7c3aed"),
    )

    # İstatistik motoru, ilgili katmanı olmayan paketleri "UNKNOWN" anahtarı
    # altında sayar (ör. bir ICMP paketinin uygulama katmanı yoktur). Ham
    # anahtar raporda anlamsız durduğu için sunumda çevrilir; bilgi ATILMAZ,
    # çünkü "kaç paketin uygulama protokolü belirlenemedi" başlı başına bir
    # bulgudur (tanınmayan/özel protokoller orada saklanır).
    _UNKNOWN_DISPLAY: Final[str] = "Belirlenemedi"

    def layered_protocol_chart(
        self,
        network: dict[str, int],
        transport: dict[str, int],
        application: dict[str, int],
    ) -> tuple[str | None, list[TableRow]]:
        """Ağ / taşıma / uygulama katmanlarının her birini ayrı ayrı gösterir.

        Neden `protocol_distribution_chart`'a ek olarak gerekli: o grafik her
        paketi TEK BİR kez, tespit edilebilen EN ÜST katmanın adıyla sayar.
        Bu, "hangi uygulama trafiği var" sorusunu yanıtlar ama katmanları
        birbirinin üstüne katlar: 233.136 TLS paketinin aynı zamanda 233.136
        TCP paketi olduğu görünmez, çünkü o paketler TCP olarak hiç sayılmaz.
        Analistin sorduğu "bu capture'da taşıma katmanında ne var" ya da
        "kaç paketin uygulama protokolü belirlenemedi" soruları o grafikten
        cevaplanamaz.

        Üç dağılımın her biri toplam paket sayısına eşittir (eksik katmanlar
        "UNKNOWN" altında sayılır), dolayısıyla katmanlar birbiriyle
        karşılaştırılabilir.

        Ölçek ve etiketleme `protocol_distribution_chart` ile aynı kuralları
        izler (koşullu logaritmik eksen, bar ucunda gerçek sayı + yüzde), ki
        iki grafik yan yana dururken aynı dilde konuşsunlar.
        """
        layers = (network, transport, application)
        if not any(layers):
            return None, []

        # barh 0. indeksi en alta koyar; ağ katmanı en üstte görünsün diye
        # katmanlar ters sırada gezilir.
        bar_labels: list[str] = []
        bar_values: list[int] = []
        bar_colors: list[str] = []
        table_data: list[TableRow] = []

        for (layer_name, color), distribution in zip(
            self._PROTOCOL_LAYERS, layers, strict=True
        ):
            if not distribution:
                continue
            layer_total = sum(distribution.values())
            items = sorted(distribution.items(), key=lambda kv: kv[1], reverse=True)
            for protocol, count in items:
                display = self._UNKNOWN_DISPLAY if protocol == "UNKNOWN" else protocol
                bar_labels.append(f"{layer_name} · {display}")
                bar_values.append(count)
                bar_colors.append(color)
                share = count / layer_total if layer_total else 0.0
                table_data.append(
                    TableRow(label=f"{layer_name} · {display}", value=f"{count:,} ({share:.1%})")
                )

        if not bar_values:
            return None, []

        # Yükseklik bar sayısına göre büyür: sabit yükseklikte 10+ bar
        # birbirine yapışıp okunmaz hale geliyordu.
        height = max(self._FIGSIZE[1], 0.34 * len(bar_values) + 1.4)
        fig, ax = plt.subplots(figsize=(self._FIGSIZE[0], height), dpi=self._DPI)

        positions = range(len(bar_values))
        bars = ax.barh(
            list(positions),
            list(reversed(bar_values)),
            color=list(reversed(bar_colors)),
        )
        ax.set_yticks(list(positions))
        ax.set_yticklabels(list(reversed(bar_labels)))
        ax.set_title("Katman Bazlı Protokol Dağılımı")

        drawn_values = list(reversed(bar_values))
        smallest = min(v for v in drawn_values if v > 0)
        if max(drawn_values) / smallest >= self._LOG_SCALE_RATIO_THRESHOLD:
            ax.set_xscale("log")
            ax.set_xlim(left=0.7, right=max(drawn_values) * 3)
            ax.set_xlabel("Paket Sayısı (logaritmik ölçek)")
        else:
            ax.set_xlim(right=max(drawn_values) * 1.25)
            ax.set_xlabel("Paket Sayısı")

        for bar, value in zip(bars, drawn_values, strict=True):
            ax.annotate(
                f"{value:,}",
                xy=(bar.get_width(), bar.get_y() + bar.get_height() / 2),
                xytext=(4, 0),
                textcoords="offset points",
                va="center",
                fontsize=8,
            )

        handles = [
            plt.Rectangle((0, 0), 1, 1, color=color)
            for (name, color), distribution in zip(self._PROTOCOL_LAYERS, layers, strict=True)
            if distribution
        ]
        names = [
            name
            for (name, _color), distribution in zip(self._PROTOCOL_LAYERS, layers, strict=True)
            if distribution
        ]
        # loc="best": barlar katman içinde azalan sırada olduğu için boş alan
        # genellikle sağ altta kalır, ama tek satırlık bir katman varsa orası
        # dolu olabilir. Sabit bir köşe seçmek yerine matplotlib'in çakışmayı
        # en aza indiren yerleşimi kullanılıyor.
        ax.legend(handles, names, title="Katman", loc="best", fontsize=8, frameon=False)

        fig.tight_layout()
        return self._to_base64(fig), table_data

    # Grafik çubuğu etiketlerinde hostname bu uzunluktan sonra kesilir;
    # aksi halde uzun bir domain adı (örn. bir CDN'in tam alt alan adı)
    # sol eksen genişliğini anlamsız şekilde büyütüp grafiği okunaksız
    # hale getirebilir. Tam (kesilmemiş) hostname her zaman yan tablodadır.
    _CHART_HOSTNAME_MAX_LEN: Final[int] = 28

    def top_hosts_chart(
        self,
        hosts: Sequence[tuple[str, int]],
        title: str,
        xlabel: str,
        value_formatter: Callable[[int], str] | None = None,
        hostname_map: dict[str, str] | None = None,
    ) -> tuple[str | None, list[TableRow]]:
        """Top-K host listesi (talker/bandwidth) için yatay bar grafiği ve tablo üretir.

        `hostname_map` verilirse (IP -> DNS içinde görülen hostname), her
        host etiketi "IP (hostname)" biçiminde zenginleştirilir. Bu, bir
        analistin sadece IP'ye bakarak trafiğin nereden geldiğini tahmin
        etmek zorunda kalmadan doğrudan görmesini sağlar. Eşleşmesi olmayan
        (DNS'te hiç görülmemiş) IP'ler değişmeden, sade IP olarak kalır.
        """
        if not hosts:
            return None, []

        top = list(hosts[: config.TOP_N_TALKERS])

        def _display_label(host: str, *, for_chart: bool) -> str:
            hostname = (hostname_map or {}).get(host)
            if not hostname:
                return host
            if for_chart and len(hostname) > self._CHART_HOSTNAME_MAX_LEN:
                hostname = hostname[: self._CHART_HOSTNAME_MAX_LEN - 1] + "…"
            return f"{host} ({hostname})"

        # barh en üstte en büyük değeri göstersin diye ters çeviriyoruz.
        labels = [_display_label(host, for_chart=True) for host, _ in reversed(top)]
        values = [count for _, count in reversed(top)]

        fig, ax = plt.subplots(figsize=self._FIGSIZE, dpi=self._DPI)
        ax.barh(labels, values, color="#2563eb")
        ax.set_title(title)
        ax.set_xlabel(xlabel)
        fig.tight_layout()

        fmt = value_formatter or (lambda v: f"{v:,}")
        table_data = [
            TableRow(label=_display_label(host, for_chart=False), value=fmt(count))
            for host, count in top
        ]
        return self._to_base64(fig), table_data

    def port_distribution_chart(
        self,
        ports: dict[int, int],
        title: str | None = None,
        color: str = "#059669",
    ) -> tuple[str | None, list[TableRow]]:
        """En sık görülen ilk N port için dikey bar grafiği ve tablo üretir.

        `title`/`color` parametreleri, aynı grafiğin TCP ve UDP port dağılımı
        için ayrı ayrı (ve görsel olarak birbirinden ayırt edilebilir şekilde)
        üretilebilmesi içindir; verilmezse başlık ve renk varsayılana düşer.
        """
        if not ports:
            return None, []

        top = sorted(ports.items(), key=lambda kv: kv[1], reverse=True)[: config.TOP_N_PORTS]
        labels = [str(port) for port, _ in top]
        values = [count for _, count in top]

        fig, ax = plt.subplots(figsize=self._FIGSIZE, dpi=self._DPI)
        ax.bar(labels, values, color=color)
        ax.set_title(title or f"Port Dağılımı (İlk {config.TOP_N_PORTS})")
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
            datetime.fromtimestamp(ts, tz=UTC).strftime("%H:%M:%S")
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

        table_data = self._build_timeline_table(items, formatted_labels)
        return self._to_base64(fig), table_data

    @staticmethod
    def _build_timeline_table(
        items: list[tuple[float, int]], formatted_labels: list[str]
    ) -> list[TableRow]:
        """Zaman çizelgesi analist tablosunu üretir.

        Bucket sayısı `config.TIMELINE_TABLE_MAX_ROWS` altındaysa birebir
        (saniye/bucket başına bir satır) gösterilir. Üzerindeyse -uzun
        capture'larda tablonun yüzlerce satıra çıkıp raporu kullanılamaz hale
        getirmemesi için- ardışık bucket'lar otomatik olarak daha geniş zaman
        dilimlerinde toplanır (sum). Grafik bu yeniden örneklemeden etkilenmez,
        tam çözünürlükle çizilmeye devam eder.
        """
        max_rows = config.TIMELINE_TABLE_MAX_ROWS
        total_buckets = len(items)

        if total_buckets <= max_rows:
            return [
                TableRow(label=label, value=f"{count:,}")
                for label, (_, count) in zip(formatted_labels, items, strict=True)
            ]

        chunk_size = math.ceil(total_buckets / max_rows)
        table_data: list[TableRow] = []
        for start in range(0, total_buckets, chunk_size):
            end = min(start + chunk_size, total_buckets)
            chunk_total = sum(count for _, count in items[start:end])
            start_label = formatted_labels[start]
            end_label = formatted_labels[end - 1]
            label = start_label if start_label == end_label else f"{start_label} – {end_label}"
            table_data.append(TableRow(label=label, value=f"{chunk_total:,}"))

        return table_data

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


def build_chart_sections(
    statistics: GeneralStatistics, chart_builder: ChartBuilder
) -> list[ChartSection]:
    """Tüm grafikleri ve bunlara ait analist detay tablolarını tek bir listede toplar.

    Reporter'ın bir metodu değil, modül seviyesinde bir fonksiyondur: HTML
    raporu (Reporter) ve PDF export'u (modules/exporters/pdf_exporter.py) AYNI
    grafik kümesini, aynı başlık ve açıklamalarla göstermek zorundadır. Aynı
    capture'ın iki adli çıktısının farklı grafikler içermesi, hangisinin
    eksik olduğu sorusunu doğurur; tek liste tanımı bu soruyu ortadan kaldırır.
    PDF'in bunun için bir Reporter (ve dolayısıyla bir Jinja2 ortamı)
    kurmasına da gerek kalmaz.
    """
    charts: list[ChartSection] = []

    img, table = chart_builder.protocol_distribution_chart(
        statistics.protocol_distribution
    )
    if img:
        charts.append(
            ChartSection(
                id="protocol_distribution",
                title="Protokol Dağılımı",
                description=(
                    "Yakalanan her paket, tespit edilebilen en üst katmanın protokolüyle "
                    "tam olarak bir kez sayılır (uygulama → taşıma → ağ katmanı). Tek bir "
                    "protokolün baskın olduğu capture'larda küçük protokollerin de "
                    "görünebilmesi için ölçek logaritmik olabilir; bar uçlarındaki "
                    "sayılar her zaman gerçek paket sayısıdır."
                ),
                image=img,
                table=table,
                val_header="Paket Sayısı",
            )
        )

    # Protokol grafiğinin hemen ardında: o grafik her paketi yalnızca en
    # üst katmanıyla sayar, bu grafik ise üç katmanın her birini ayrı ayrı
    # gösterir (bkz. ChartBuilder.layered_protocol_chart).
    img, table = chart_builder.layered_protocol_chart(
        statistics.network_protocol_distribution,
        statistics.transport_protocol_distribution,
        statistics.application_protocol_distribution,
    )
    if img:
        charts.append(
            ChartSection(
                id="layered_protocol_distribution",
                title="Katman Bazlı Protokol Dağılımı",
                description=(
                    "Ağ, taşıma ve uygulama katmanlarının her biri ayrı ayrı. Bir üstteki "
                    "grafik her paketi yalnızca en üst katmanıyla saydığı için, örneğin "
                    "TLS paketlerinin aynı zamanda TCP paketi olduğu orada görünmez. "
                    "Uygulama katmanındaki \"Belirlenemedi\" satırı, protokolü tespit "
                    "edilemeyen paketleri gösterir."
                ),
                image=img,
                table=table,
                val_header="Paket Sayısı",
            )
        )

    img, table = chart_builder.top_hosts_chart(
        statistics.top_source_ips,
        "En Aktif Hostlar (Top Talkers)",
        "Paket Sayısı",
        hostname_map=statistics.ip_hostname_map,
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

    img, table = chart_builder.top_hosts_chart(
        statistics.top_bandwidth_hosts,
        "En Yüksek Bant Genişliği Kullananlar",
        "Boyut",
        value_formatter=_format_bytes,
        hostname_map=statistics.ip_hostname_map,
    )
    if img:
        charts.append(
            ChartSection(
                id="top_bandwidth_hosts",
                title="En Yüksek Bant Genişliği Kullananlar",
                description="Toplam veri aktarım hacmi açısından ağ bant genişliğini en çok tüketen hostlar.",
                image=img,
                table=table,
                val_header="Toplam Boyut",
            )
        )

    img, table = chart_builder.port_distribution_chart(
        dict(statistics.top_tcp_ports),
        title=f"TCP Port Dağılımı (İlk {config.TOP_N_PORTS})",
    )
    if img:
        charts.append(
            ChartSection(
                id="port_distribution",
                title="TCP Port Dağılımı",
                description="Trafikte en sık hedef alınan ve kullanılan ilk TCP portlarının paket yoğunluğu.",
                image=img,
                table=table,
                val_header="Paket Sayısı",
            )
        )

    # `top_udp_ports` istatistik motorunda hesaplanıyordu ama rapora hiç
    # girmiyordu: DNS, DHCP, NTP ve günümüzde web trafiğinin büyük
    # bölümünü taşıyan QUIC/HTTP3 UDP üzerinde koşar, dolayısıyla yalnızca
    # TCP portlarını göstermek capture'ın önemli bir kısmını görünmez
    # bırakıyordu.
    img, table = chart_builder.port_distribution_chart(
        dict(statistics.top_udp_ports),
        title=f"UDP Port Dağılımı (İlk {config.TOP_N_PORTS})",
        color="#7c3aed",
    )
    if img:
        charts.append(
            ChartSection(
                id="udp_port_distribution",
                title="UDP Port Dağılımı",
                description=(
                    "UDP üzerinde en sık görülen portlar (DNS, DHCP, NTP, QUIC/HTTP3 vb.) "
                    "ve paket yoğunlukları."
                ),
                image=img,
                table=table,
                val_header="Paket Sayısı",
            )
        )

    img, table = chart_builder.timeline_chart(statistics.timeline)
    if img:
        charts.append(
            ChartSection(
                id="timeline",
                title="Zaman Çizelgesi (Paket Trafiği)",
                description=(
                    "Analiz edilen zaman aralığı boyunca ağ trafiğinde meydana gelen "
                    "anlık yoğunlaşma ve dalgalanmalar."
                ),
                image=img,
                table=table,
                val_header="Paket Sayısı",
            )
        )

    return charts


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
        sha256: str | None = None,
    ) -> Path:
        """Analiz sonuçlarından tek dosyalık HTML rapor üretir.

        Args:
            statistics: Statistics modülünün ürettiği genel istatistikler.
            findings: Threat Detector'ın ürettiği bulgular (sıra önemsiz,
                bu metod severity'ye göre yeniden sıralar).
            threat_intel: Threat Intel modülünden gelen IOC sonuçları.
            source_file: Analiz edilen PCAP kaynak dosya yolu.
            analysis_duration: Analiz süresi (saniye cinsinden).
            sha256: Kaynak dosyanın önceden hesaplanmış SHA-256 özeti.
                Verilmezse burada hesaplanır. Parametre, aynı çalıştırmada
                hem HTML raporu hem de JSON/CSV/PDF export'ları üretilirken
                GB boyutundaki bir delil dosyasının iki kez baştan sona
                okunmasını önlemek için vardır (bkz. main.py).

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
            sha256=sha256 if sha256 is not None else _compute_sha256(source_file),
        )

        # Çıktı klasörü (clean / malicious) capture'ın üst klasöründen türetilir.
        # Kural export katmanıyla PAYLAŞILIR (modules/output_paths.py): aynı
        # capture'ın HTML raporu ile JSON/CSV/PDF çıktıları aynı klasöre düşmeli.
        output_path = resolve_output_dir(source_file) / f"{source_file.stem}_report.html"

        logger.info(
            "Generating report for %s (%d packets)...",
            metadata.source_file,
            statistics.total_packets,
        )
        self._validate_inputs(statistics, metadata, output_path)

        # Risk skoru DAİMA ham, gruplanmamış bulgu listesinden hesaplanır;
        # aksi halde tekrarlayan tespitler tek bir olay gibi sayılıp skor
        # yanlışlıkla düşer.
        risk_summary = compute_risk_summary(findings)

        # Rapor GÖRÜNÜMÜ için: aynı (rule_id, source, destination) için
        # tekrar eden bulgular tek satırda özetlenir, ardından severity'ye
        # göre sıralanır ve şablonun beklediği (formatted_timestamp vb.)
        # sunum alanlarıyla zenginleştirilir.
        display_findings = self._sort_findings_by_severity(
            _group_recurring_findings(findings)
        )
        findings_rows = _prepare_findings_for_template(
            display_findings, statistics.ip_hostname_map
        )

        charts_list = self._build_charts_list(statistics)

        html = self._render(
            metadata=metadata,
            statistics=_prepare_statistics_for_template(statistics),
            findings=findings_rows,
            threat_intel=_prepare_threat_intel_for_template(threat_intel),
            risk_summary=risk_summary,
            charts=charts_list,
        )
        self._write(html, output_path)

        logger.info(
            "Rapor başarıyla oluşturuldu: %s (%d bulgu, %d satırda gruplandı, risk seviyesi: %s)",
            output_path,
            len(findings),
            len(findings_rows),
            risk_summary.risk_level,
        )
        return output_path

    def _build_charts_list(self, statistics: GeneralStatistics) -> list[ChartSection]:
        """Grafik bölümlerini üretir (bkz. modül seviyesindeki build_chart_sections)."""
        return build_chart_sections(statistics, self._chart_builder)

    def _render(
        self,
        *,
        metadata: ReportMetadata,
        statistics: dict[str, Any],
        findings: list[dict[str, Any]],
        threat_intel: list[ThreatIntelSummary],
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
