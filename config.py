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