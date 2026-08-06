"""
Proje yapılandırma ayarları ve sabit değerler.
"""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = BASE_DIR / "samples"
REPORTS_DIR = BASE_DIR / "reports"
TEMPLATES_DIR = BASE_DIR / "templates"
LOGS_DIR = BASE_DIR / "logs"

# Tek sürüm kaynağı. Daha önce üç ayrı yerde üç FARKLI değer vardı
# (main.py banner "1.1.0-refactored", pyproject.toml "1.2.0",
# reporter.py "1.2.0-forensic"); rapordaki "Araç Sürümü" alanı adli bir
# belgede yer aldığı için hangi sürümün üretildiği tek bir yerden
# okunabilmelidir.
TOOL_VERSION = "1.2.0"

# ==========================
# General Statistics
# ==========================

TOP_N_TALKERS = 10
TOP_N_IPS = 10
TOP_N_PORTS = 10

# --------------------------------------------------------------------
# Threat Detection: Port Scan
# --------------------------------------------------------------------
# Aynı kaynak IP'nin (src_ip), aynı hedef IP'ye (dst_ip),
# belirtilen zaman penceresi içerisinde erişmeye çalıştığı benzersiz
# hedef port sayısı bu eşiği aşarsa Port Scan olarak değerlendirilir.
PORT_SCAN_TIME_WINDOW_SECONDS: int = 60
PORT_SCAN_PORT_THRESHOLD: int = 15

# Ephemeral (geçici/istemci) port aralığının başlangıcı. Linux varsayılanı
# 32768-60999, IANA önerisi 49152-65535'tir; ikisini de kapsayacak şekilde
# daha geniş (daha temkinli) olan alt sınır seçilmiştir.
#
# NEDEN GEREKLİ: Bir port taramasında paketler tarayıcının EPHEMERAL kaynak
# portundan hedefin SERVİS portuna gider. Bunun tam TERSİ yön -yani servis
# portundan ephemeral porta- neredeyse her zaman bir isteğe verilen
# YANITTIR. Bu ayrım yapılmadığında, yerel DNS sunucusunun istemciye
# gönderdiği sıradan cevaplar (53 -> 33615, 53 -> 38777, 53 -> 50922 ...)
# "60 saniyede 23 farklı porta erişim" gibi görünür ve tamamen temiz bir
# capture HIGH severity "Port Taraması" bulgusuyla KRİTİK risk seviyesine
# çıkar (bkz. threat_detector._is_probable_response_packet).
EPHEMERAL_PORT_MIN: int = 32768

# --------------------------------------------------------------------
# Threat Detection: Diğer Kurallar
# --------------------------------------------------------------------
SYN_SCAN_TIME_WINDOW_SECONDS: int = 60
SYN_SCAN_PORT_THRESHOLD: int = 10

ICMP_FLOOD_TIME_WINDOW_SECONDS: int = 10
ICMP_FLOOD_PACKET_THRESHOLD: int = 100

FAILED_TCP_TIME_WINDOW_SECONDS: int = 60
FAILED_TCP_ATTEMPT_THRESHOLD: int = 20

DNS_TUNNEL_TIME_WINDOW_SECONDS: int = 60
DNS_TUNNEL_QUERY_COUNT_THRESHOLD: int = 30
DNS_TUNNEL_SUSPICIOUS_QTYPES: tuple[str, ...] = ("TXT", "NULL", "CNAME")

# "Temel alan adı" (base_domain) çıkarımı normalde sondan iki etikettir
# (örn. "sub.evil.com" -> "evil.com"). Ancak çok parçalı public suffix'lere
# (ikinci seviye TLD) sahip alan adlarında ("sub.firma.com.tr",
# "sub.firma.co.uk") sondan iki etiket yalnızca suffix'in kendisidir
# ("com.tr", "co.uk"); bu durumda TÜM ".com.tr" alan adları aynı kovaya
# düşer ve birbiriyle hiç ilgisi olmayan şirketlerin DNS trafiği
# yanlışlıkla tek bir "domain" olarak gruplanır (bkz. threat_detector.py
# _detect_dns_tunneling / _compute_base_domain). Bu liste, tam bir Public
# Suffix List (PSL) değildir — internet bağlantısı gerektirmeyen,
# offline çalışma gereksinimine uygun, en yaygın çok parçalı suffix'leri
# kapsayan küçük, statik bir tablodur. Kapsanmayan bir suffix ile
# karşılaşılırsa eski (sondan-iki-etiket) davranışa sessizce geri döner.
DNS_TUNNEL_MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset({
    # Türkiye
    "com.tr", "gov.tr", "org.tr", "net.tr", "edu.tr", "web.tr", "info.tr", "gen.tr",
    # Birleşik Krallık
    "co.uk", "org.uk", "gov.uk", "ac.uk", "net.uk", "sch.uk",
    # Diğer yaygın ikinci seviye TLD'ler
    "co.jp", "co.kr", "co.in", "co.nz", "co.za", "com.au", "com.br", "com.cn",
    "com.mx", "com.ar", "com.sg", "com.hk",
})

DGA_MIN_LABEL_LENGTH: int = 12

# --------------------------------------------------------------------
# Threat Intelligence
# --------------------------------------------------------------------
# 1. Threat Intelligence Timeout
THREAT_INTEL_REQUEST_TIMEOUT_SECONDS = 3

# 2. Retry Ayarları
THREAT_INTEL_MAX_RETRIES = 1
THREAT_INTEL_BACKOFF_FACTOR_SECONDS = 1
THREAT_INTEL_RETRY_STATUS_CODES = (
    429,
    500,
    502,
    503,
    504,
)

# 3. HTTP Session Pool
THREAT_INTEL_POOL_CONNECTIONS = 10
THREAT_INTEL_POOL_MAXSIZE = 10
THREAT_INTEL_ALLOWED_METHODS = (
    "GET",
    "POST",
)

# 4. API Base URL'leri
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# 5. Provider Ayarları
ABUSEIPDB_MAX_AGE_DAYS = 90
OTX_MAX_CATEGORY_COUNT = 20

# AbuseIPDB'nin "reports[].categories" alanındaki sabit sayısal kategori
# kodlarının insan tarafından okunabilir karşılıkları (bkz. AbuseIPDB API
# dokümantasyonu / https://www.abuseipdb.com/categories). Bu liste
# AbuseIPDB tarafında zaman zaman güncellenebilir; haritada olmayan bir
# kod threat_intel.py tarafında "UNKNOWN_<id>" olarak korunur, asla
# sessizce kaybolmaz.
ABUSEIPDB_CATEGORY_MAP: dict[int, str] = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}

# 6. Environment Variable İsimleri
VIRUSTOTAL_API_KEY_ENV = "VT_API_KEY"
ABUSEIPDB_API_KEY_ENV = "ABUSEIPDB_API_KEY"
OTX_API_KEY_ENV = "OTX_API_KEY"


TIMELINE_BUCKET_SECONDS = 1

# Zaman çizelgesi tablosu, uzun yakalamalarda (örn. saniye başına 1 bucket
# ile 5+ dakikalık capture) yüzlerce satıra çıkabilir. Grafik zaten tam
# çözünürlükle çizilir; tablo ise analist okunabilirliği için bu satır
# sayısını aşarsa otomatik olarak daha geniş zaman dilimlerine (bucket'lara)
# yeniden örneklenir (bkz. reporter.ChartBuilder._build_timeline_table).
TIMELINE_TABLE_MAX_ROWS = 40

for directory in (SAMPLES_DIR, REPORTS_DIR, TEMPLATES_DIR, LOGS_DIR):
    directory.mkdir(parents=True, exist_ok=True)

SUPPORTED_EXTENSIONS = (".pcap", ".pcapng")

# --------------------------------------------------------------------
# Büyük capture uyarı eşiği
# --------------------------------------------------------------------
# Ayrıştırma akış halinde (PcapReader) yapılır, ancak üretilen PacketInfo
# nesnelerinin TAMAMI bellekte tutulur; tespit kuralları capture'ın bütününe
# bakabilmek zorunda olduğu için. Ölçüm (300 bin paket, gerçekçi IP
# çeşitliliği): paket başına ~291 bayt, tespit sırasında zirve ~480 bayt.
#
# Bellek paket SAYISIYLA orantılıdır, dosya boyutuyla DEĞİL. Bu ayrım uyarının
# nasıl yazıldığını belirler, çünkü iki uç arasındaki fark çok büyüktür:
#
#   - 64 baytlık minimum paketlerden oluşan bir dosyada MB başına ~16.000 paket
#     vardır; paket başına ~300 bayt ile dosya boyutunun ~5 KATI bellek gerekir.
#   - Ölçüm (1,3 GB'lık gerçek capture, ortalama paket ~5,7 KB): 236.843 paket,
#     zirve 179 MB RSS -- yani dosya boyutunun ~0,14 KATI.
#
# Tek bir çarpanla "X MB gerekecek" demek bu yüzden yanıltıcıdır: kötümser uç,
# büyük paketli capture'larda gerçek kullanımın 30 katından fazlasını gösterip
# analisti dosyayı gereksiz yere bölmeye iter. Uyarı bu nedenle tek bir sayı
# değil, "paket boyutuna göre şu aralıkta" bilgisi verir (bkz.
# parser._warn_if_large).
#
# Eşik aşıldığında analiz hiçbir koşulda REDDEDİLMEZ -- meşru büyük bir delili
# işlemeyi reddetmek adli bir araçta kabul edilemez; amaç yalnızca, süreç OOM
# ile kesilirse analistin sebebini bilmesidir.
LARGE_CAPTURE_WARNING_BYTES = 500 * 1024 * 1024  # 500 MB
# Minimum boyutlu (64 bayt) paketlerden oluşan capture için üst sınır.
LARGE_CAPTURE_WORST_CASE_MEMORY_FACTOR = 5
# 1,3 GB'lık gerçek bir capture üzerinde ölçülen tipik oran (ortalama ~5,7 KB
# paket). Alt sınır olarak değil, "büyük paketli capture'larda beklenen"
# değer olarak sunulur.
LARGE_CAPTURE_TYPICAL_MEMORY_FACTOR = 0.15

PROTOCOL_MAP = {
    1: "ICMP",
    2: "IGMP",
    4: "IP-in-IP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    88: "EIGRP",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    132: "SCTP",
}

DNS_QTYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
}

UNKNOWN_PROTOCOL = "OTHER"
DEFAULT_FLAGS = "NONE"

# Eşik, sabit bir zaman penceresi İÇİNDE aşılması gereken byte miktarıdır
# (bkz. threat_detector._detect_exfiltration). Bir pencere yok sayılırsa
# (eski davranış) tüm capture boyunca biriken toplam byte eşikle
# karşılaştırılır; bu da saatlerce süren normal bir indirme/video akışını
# dahi CRITICAL olarak işaretler. 5 dakikalık pencere, "kısa sürede
# yüksek hacim" olan gerçek sızdırma davranışını "yavaş ve sürekli" olan
# sıradan trafikten ayırmaya yetecek kadar sıkı, yanlış-pozitifi
# azaltacak kadar da geniştir.
EXFILTRATION_TIME_WINDOW_SECONDS: int = 300
EXFILTRATION_THRESHOLD = 50 * 1024 * 1024
LONG_DOMAIN_LENGTH = 50
DGA_ENTROPY_THRESHOLD = 3.5

# Rapor dosya adı reporter.py tarafından kaynak capture'ın adından türetilir
# (`<stem>_report.html`), bu yüzden burada sabit bir rapor adı tutulmaz.
DEFAULT_LOG_NAME = "analysis.log"
