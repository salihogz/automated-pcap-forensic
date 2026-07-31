"""
Proje yapılandırma ayarları ve sabit değerler.
"""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = BASE_DIR / "samples"
REPORTS_DIR = BASE_DIR / "reports"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
LOGS_DIR = BASE_DIR / "logs"

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

# --------------------------------------------------------------------
# Threat Intelligence
# --------------------------------------------------------------------
# 1. Threat Intelligence Timeout
THREAT_INTEL_REQUEST_TIMEOUT_SECONDS = 10

# 2. Retry Ayarları
THREAT_INTEL_MAX_RETRIES = 3
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
URLHAUS_BASE_URL = "https://urlhaus-api.abuse.ch/v1"

# 5. Provider Ayarları
ABUSEIPDB_MAX_AGE_DAYS = 90
OTX_MAX_CATEGORY_COUNT = 20

# 6. Environment Variable İsimleri
VIRUSTOTAL_API_KEY_ENV = "VT_API_KEY"
ABUSEIPDB_API_KEY_ENV = "ABUSEIPDB_API_KEY"
OTX_API_KEY_ENV = "OTX_API_KEY"
URLHAUS_API_KEY_ENV = "URLHAUS_API_KEY"


TIMELINE_BUCKET_SECONDS = 1
for directory in (SAMPLES_DIR, REPORTS_DIR, TEMPLATES_DIR, STATIC_DIR, LOGS_DIR):
    directory.mkdir(parents=True, exist_ok=True)

SUPPORTED_EXTENSIONS = (".pcap", ".pcapng")

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

UNKNOWN_PROTOCOL = "OTHER"
DEFAULT_FLAGS = "NONE"

EXFILTRATION_THRESHOLD = 50 * 1024 * 1024
LONG_DOMAIN_LENGTH = 50
DGA_ENTROPY_THRESHOLD = 3.5

DEFAULT_REPORT_NAME = "forensic_report.html"
DEFAULT_LOG_NAME = "analysis.log"