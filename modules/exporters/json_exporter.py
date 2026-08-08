# modules/exporters/json_exporter.py
"""
Automated PCAP Forensic Analysis Tool - JSON export.

HTML/PDF raporlar bir ANALİSTİN okuması için üretilir; bu biçim bir
MAKİNENİN okuması için üretilir (SIEM'e besleme, başka araçlarla
korelasyon, toplu analizde diff alma). Aradaki fark somut sonuçlar doğurur:

* Zaman damgaları ham epoch olarak korunur, "08.08.2026 15:04:05" gibi
  yerelleştirilmiş metne çevrilmez -- tüketici kendi biçimini seçebilmeli.
* Bulgular HAM haliyle yazılır: rapor görünümünde tekrar eden tespitler tek
  satırda gruplanır, burada gruplanmaz. Grupsuz liste kayıpsızdır; bir
  tüketici isterse kendisi gruplar, ama gruplanmış veriden ham olayları geri
  getiremez.
* ``is_malicious`` üç durumludur ve JSON'da ``true`` / ``false`` / ``null``
  olarak korunur. ``null`` "sağlayıcı hüküm veremedi" demektir ve ASLA
  ``false`` ("temiz") ile birleştirilmez (bkz. threat_intel.py).

Şema sürümlenmiştir (``schema_version``): alan eklemek sürümü artırmaz,
ancak bir alanın anlamı veya tipi değişirse artırılmalıdır ki tüketiciler
kırılmayı sessizce değil açıkça görsün.
"""
import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any, ClassVar, Final

from modules.exporters.base import Exporter, ExportError, ExportPayload
from modules.reporter import _prepare_threat_intel_for_template

logger = logging.getLogger(__name__)

# Şema sürümü. Bkz. modül docstring'i: yalnızca GERİYE UYUMSUZ değişikliklerde
# (alan silme, tip/anlam değiştirme) artırılır.
_SCHEMA_VERSION: Final[int] = 1

_TOOL_NAME: Final[str] = "Automated PCAP Forensic Analysis Tool"


def _json_default(value: Any) -> Any:
    """`json` modülünün yerel olarak seri hale getiremediği tipleri çevirir.

    Fail Fast: tanınmayan bir tip sessizce ``str(value)``'ya düşürülmez.
    Ham Python ``repr``'ının çıktıya sızması bu projede daha önce yaşanmış
    bir hatadır (bkz. reporter.py `_format_evidence_value`); makine tarafından
    okunan bir çıktıda "<Foo object at 0x7f...>" gibi bir değer, veriyi
    sessizce kullanılamaz hale getirir. Bilinmeyen tip TypeError'a düşer ve
    ExportError'a çevrilir.
    """
    # datetime / date: ISO 8601. NormalizedIOCResult.queried_at ve last_seen
    # bu yoldan geçer.
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    raise TypeError(f"JSON'a çevrilemeyen tip: {type(value).__name__}")


def _serialize_finding(finding: Any) -> dict[str, Any]:
    """Tek bir ThreatFinding'i JSON'a hazır dict'e çevirir."""
    record = asdict(finding)
    # severity bir `(str, Enum)` üyesidir; json onu zaten string olarak yazar,
    # ancak bu davranış Enum tabanının bir yan etkisidir. Açıkça `.value`
    # yazmak, ileride Enum tabanı değişirse çıktının sessizce
    # "ThreatSeverity.CRITICAL"e dönüşmesini engeller.
    record["severity"] = finding.severity.value
    return record


def _serialize_provider_result(result: Any) -> dict[str, Any]:
    """Tek bir NormalizedIOCResult'ı JSON'a hazır dict'e çevirir."""
    return {
        "provider": result.source,
        # Üç durumlu: true / false / null. null "hüküm verilemedi" demektir.
        "is_malicious": result.is_malicious,
        # Sağlayıcıya özgü, NORMALIZE EDİLMEMİŞ ham değer: VirusTotal'de
        # işaretleyen motor sayısı, AbuseIPDB'de 0-100 güven skoru, OTX'te
        # pulse sayısı. Üçü farklı ölçektir, doğrudan karşılaştırılamaz.
        "raw_score": result.raw_score,
        "confidence": result.confidence,
        "categories": list(result.categories),
        "last_seen": result.last_seen,
        "queried_at": result.queried_at,
        "error_code": result.provider_error_code.value if result.provider_error_code else None,
        "error_message": result.provider_error_message,
    }


class JSONExporter(Exporter):
    """Analiz sonucunun tamamını tek bir makine-okunur JSON dosyasına yazar."""

    name: ClassVar[str] = "json"

    def export(self, payload: ExportPayload, output_dir: Path) -> list[Path]:
        self._prepare_output_dir(output_dir)
        output_path = self._target_path(payload, output_dir, "_report.json")

        document = self._build_document(payload)

        try:
            # ensure_ascii=False: Türkçe bulgu başlıkları ve açıklamaları
            # "ı" kaçışları yerine okunabilir kalsın (dosya zaten UTF-8).
            serialized = json.dumps(document, ensure_ascii=False, indent=2, default=_json_default)
        except (TypeError, ValueError) as exc:
            raise ExportError(f"Analiz sonucu JSON'a serileştirilemedi: {exc}") from exc

        try:
            output_path.write_text(serialized + "\n", encoding="utf-8")
        except OSError as exc:
            raise ExportError(f"JSON çıktısı yazılamadı: {output_path} ({exc})") from exc

        logger.info("JSON export'u oluşturuldu: %s", output_path)
        return [output_path]

    @staticmethod
    def _build_document(payload: ExportPayload) -> dict[str, Any]:
        """Payload'ı sürümlenmiş JSON belge yapısına dönüştürür."""
        intel_summaries = _prepare_threat_intel_for_template(payload.threat_intel)

        return {
            "schema_version": _SCHEMA_VERSION,
            "tool": {
                "name": _TOOL_NAME,
                "version": payload.tool_version,
            },
            "analysis": {
                "source_file": payload.source_file.name,
                # Chain of custody: kaynak delilin bütünlük özeti. Hesaplanamadıysa
                # null -- alan hiç yazılmamaktansa açıkça "yok" demek daha dürüst.
                "sha256": payload.sha256,
                "generated_at": payload.generated_at,
                "duration_seconds": payload.analysis_duration_seconds,
            },
            "risk_summary": {
                "total_findings": payload.risk_summary.total_findings,
                "severity_counts": payload.risk_summary.severity_counts,
                # Sınırsız ağırlıklı toplam (20 HIGH bulgu = 300). Ölçeklenmiş
                # ya da 100'e kırpılmış DEĞİLDİR; eşik tablosu bu ham değere
                # göre kalibre edilmiştir (bkz. reporter.py).
                "risk_score": payload.risk_summary.risk_score,
                "risk_level": payload.risk_summary.risk_level,
            },
            # GeneralStatistics.to_dict(): `timeline` anahtarları float epoch
            # değerleridir; JSON nesne anahtarları string olmak zorunda olduğu
            # için json modülü bunları "1754640000.0" gibi stringlere çevirir.
            # Değer kaybı yoktur, ancak tüketici anahtarları float'a geri
            # çevirmelidir.
            "statistics": asdict(payload.statistics),
            "findings": [_serialize_finding(finding) for finding in payload.findings],
            "threat_intel": [
                {
                    "ip": summary.ip,
                    # Uzlaşı reporter.py'de hesaplanır; HTML raporla birebir
                    # aynı etiketin çıkmasının tek garantisi budur.
                    "consensus": {
                        "label": summary.consensus_label,
                        "detail": summary.consensus_detail,
                        "total_providers": summary.total_providers,
                        # Payda: YANIT VEREN sağlayıcı sayısı, yapılandırılmış
                        # olan değil. Zaman aşımına uğrayan bir sağlayıcı "temiz
                        # dedi" sayılmaz.
                        "answered_providers": summary.answered_providers,
                        "malicious_providers": summary.malicious_providers,
                    },
                    "providers": [_serialize_provider_result(result) for result in summary.results],
                }
                for summary in intel_summaries
            ],
        }
