"""
Threat Intelligence - IOC Enrichment Modülü.

Bu modül bir IP adresini birden fazla açık kaynak Threat Intelligence
sağlayıcısına (VirusTotal, AbuseIPDB, AlienVault OTX, URLHaus) sorgular,
her sağlayıcının kendine özgü yanıt şemasını ortak bir veri modeline
(``NormalizedIOCResult``) dönüştürür ve sonuçları liste halinde döndürür.

Bu sürümün kapsamı SADECE enrichment ile sınırlıdır:

    IP -> Provider sorguları -> Normalize edilmiş IOC sonuçları

Bu modül; skor hesaplama, severity belirleme, ThreatFinding üretimi,
raporlama veya main.py entegrasyonu YAPMAZ. Bu sorumluluklar
kasıtlı olarak sonraki fazlara bırakılmıştır (YAGNI).

API anahtarları yalnızca .env dosyasından okunur ve hiçbir koşulda
loglanmaz. Tüm HTTP istekleri ``verify=True`` ile SSL doğrulamalı
yapılır; SSL doğrulamasının kapatılması bu modülde desteklenmez.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import config

logger = logging.getLogger(__name__)

type IPAddressType = ipaddress.IPv4Address | ipaddress.IPv6Address


# ======================================================================
# CONSTANTS & ENUMS
# ======================================================================


class ProviderErrorCode(str, Enum):
    """Provider hataları için standartlaştırılmış hata kodları."""

    TIMEOUT = "TIMEOUT"
    CONNECTION_ERROR = "CONNECTION_ERROR"
    HTTP_ERROR = "HTTP_ERROR"
    REQUEST_ERROR = "REQUEST_ERROR"
    PARSE_ERROR = "PARSE_ERROR"
    UNEXPECTED_STATUS = "UNEXPECTED_STATUS"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


# ======================================================================
# DATA MODEL
# ======================================================================


@dataclass(frozen=True, slots=True)
class NormalizedIOCResult:
    """Tüm Threat Intel provider'larının döndürdüğü ortak, normalize edilmiş sonuç.

    Bu dataclass ``ThreatFinding`` ile karıştırılmamalıdır; ThreatFinding
    yerel trafik analizinden üretilen tehdit bulgularını temsil ederken,
    bu sınıf dış kaynaklı IOC (Indicator of Compromise) zenginleştirme
    sonucunu temsil eder. Skorlama ve severity hesaplaması bu fazda
    kasıtlı olarak yapılmaz; ``raw_score`` provider'a özgü ham değeri
    olduğu gibi taşır.

    Attributes:
        source: Sonucu üreten provider adı (örn. "VirusTotal").
        ip: Sorgulanan IP adresi.
        is_malicious: Provider'ın kötü niyetli olarak işaretleyip
            işaretlemediği. Provider yorum yapamıyorsa (ör. "no data"),
            None olarak bırakılır; False, "temiz" anlamına gelmez.
        raw_score: Provider'a özgü, normalize edilmemiş ham skor.
        categories: Provider'ın döndürdüğü tehdit kategorisi/etiket listesi.
        last_seen: Provider'ın bu IOC'yi en son gördüğü zaman (varsa).
        queried_at: Bu sonucun servis tarafından üretildiği zaman (UTC).
        provider_error_code: Sorgu başarısız olduysa veya sonuç güvenilir
            şekilde ayrıştırılamadıysa hata kodu. Başarılı sonuçlarda None.
        provider_error_message: Sorgu başarısız olduysa veya sonuç güvenilir
            şekilde ayrıştırılamadıysa detaylı hata mesajı. Başarılı sonuçlarda None.
        confidence: Provider'ın kendi güven skoru (varsa), 0.0-1.0 aralığında.
    """

    source: str
    ip: str
    is_malicious: bool | None
    raw_score: float | int | None
    categories: tuple[str, ...]
    last_seen: datetime | None
    queried_at: datetime
    provider_error_code: ProviderErrorCode | None
    provider_error_message: str | None
    confidence: float | None

    @property
    def error_message(self) -> str | None:
        """Geriye dönük test uyumluluğu için provider_error_message property'si."""
        return self.provider_error_message


# ======================================================================
# PARSING HELPERS
# ======================================================================


def _utc_now() -> datetime:
    """Mevcut UTC datetime nesnesini döndürür."""
    return datetime.now(timezone.utc)


def _safe_int(value: Any, default: int | None = None) -> int | None:
    """Değeri güvenli şekilde integer'a dönüştürür; başarısızlıkta default değer döner ve loglar."""
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        logger.warning("Tam sayıya dönüştürülemeyen değer: %r", value)
        return default


def _parse_unix_timestamp(value: Any) -> datetime | None:
    """Unix timestamp değerini UTC datetime'a çevirir; başarısızlıkta None döner."""
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        logger.warning("Unix timestamp ayrıştırılamadı: %r", value)
        return None


def _parse_iso8601(value: Any) -> datetime | None:
    """ISO 8601 formatındaki string değeri datetime'a çevirir; başarısızlıkta None döner."""
    if not value or not isinstance(value, str):
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except ValueError:
        logger.warning("ISO 8601 tarih ayrıştırılamadı: %r", value)
        return None


def _parse_urlhaus_datetime(value: Any) -> datetime | None:
    """URLHaus'a özgü 'YYYY-MM-DD HH:MM:SS UTC' formatını ayrıştırır."""
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S UTC")  # noqa: DTZ007
        return parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        logger.warning("URLHaus tarih formatı ayrıştırılamadı: %r", value)
        return None


def _calculate_vt_confidence(stats: dict[str, Any]) -> float | None:
    """VirusTotal analiz istatistiklerinden güven skoru hesaplar."""
    if not stats:
        return None

    malicious_count = _safe_int(stats.get("malicious"), default=0) or 0
    suspicious_count = _safe_int(stats.get("suspicious"), default=0) or 0
    harmless_count = _safe_int(stats.get("harmless"), default=0) or 0
    undetected_count = _safe_int(stats.get("undetected"), default=0) or 0

    total_relevant_votes = malicious_count + suspicious_count + harmless_count + undetected_count
    if total_relevant_votes <= 0:
        return None

    return round((malicious_count + suspicious_count) / total_relevant_votes, 4)


def _safe_get_json_key(payload: Any, *keys: str) -> str | None:
    """Nested dict yapıları içerisinden sırasıyla verilen key dizisini arar ve string döndürür."""
    curr = payload
    for k in keys:
        if isinstance(curr, dict) and k in curr:
            curr = curr[k]
        else:
            return None
    return str(curr) if curr is not None else None


def _extract_error_detail(response: requests.Response) -> str:
    """4xx/5xx yanıtlarından JSON gövdesindeki hata mesajlarını/listelerini birleştirerek okur."""
    try:
        payload = response.json()
        if isinstance(payload, dict):
            if "errors" in payload and isinstance(payload["errors"], list):
                extracted = []
                for item in payload["errors"]:
                    if isinstance(item, dict):
                        extracted.append(str(item.get("detail") or item.get("message") or item))
                    elif item:
                        extracted.append(str(item))
                if extracted:
                    return " / ".join(extracted)

            err_detail = (
                _safe_get_json_key(payload, "error", "message")
                or _safe_get_json_key(payload, "error", "detail")
                or _safe_get_json_key(payload, "error")
                or _safe_get_json_key(payload, "message")
                or _safe_get_json_key(payload, "detail")
            )
            if err_detail:
                return err_detail
    except (ValueError, requests.exceptions.JSONDecodeError):
        pass

    return response.reason or f"HTTP {response.status_code}"


# ======================================================================
# PROVIDER BASE
# ======================================================================


class ThreatIntelProvider(ABC):
    """Tüm Threat Intel provider'larının uyması gereken ortak sözleşme."""

    name: str = "Unknown"

    def __init__(self, session: requests.Session, api_key: str | None) -> None:
        self._session = session
        self._api_key = api_key

    def is_configured(self) -> bool:
        """API anahtarı tanımlı mı? Tanımlı değilse provider sorgulanmaz."""
        return bool(self._api_key)

    @abstractmethod
    def query(self, ip: str | IPAddressType) -> NormalizedIOCResult | None:
        """Verilen IP'yi provider'a sorgular ve normalize edilmiş sonucu döndürür."""
        raise NotImplementedError

    def _log_warning(self, message: str, *args: Any) -> None:
        """Provider'a özel ortak loglama yardımcısı (Lazy formatting)."""
        logger.warning("[%s] " + message, self.name, *args)

    def _extract_provider_error(self, response: requests.Response) -> str:
        """Provider'a özgü hata JSON şemasını ayrıştırır. Alt sınıflar override edebilir."""
        return _extract_error_detail(response)

    def _execute_request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> tuple[requests.Response | None, ProviderErrorCode | None, str | None]:
        """Ortak, güvenli HTTP çağrısı."""
        timeout = config.THREAT_INTEL_REQUEST_TIMEOUT_SECONDS
        try:
            response = self._session.request(
                method,
                url,
                timeout=timeout,
                verify=True,
                **kwargs,
            )

            if response.ok:
                return response, None, None

            error_msg = self._extract_provider_error(response)
            formatted_msg = f"HTTP {response.status_code}: {error_msg}"
            self._log_warning("HTTP isteği başarısız oldu: %s", formatted_msg)
            return None, ProviderErrorCode.HTTP_ERROR, formatted_msg

        except requests.exceptions.Timeout:
            self._log_warning("İstek zaman aşımına uğradı.")
            return None, ProviderErrorCode.TIMEOUT, "Request timed out"
        except requests.exceptions.ConnectionError:
            self._log_warning("Bağlantı hatası oluştu.")
            return None, ProviderErrorCode.CONNECTION_ERROR, "Connection failed"
        except requests.exceptions.RequestException as exc:
            self._log_warning("Beklenmeyen istek hatası: %s", exc)
            return None, ProviderErrorCode.REQUEST_ERROR, f"Request exception: {exc}"

    def _build_error_result(
        self,
        ip: str,
        error_code: ProviderErrorCode,
        error_message: str,
        queried_at: datetime,
    ) -> NormalizedIOCResult:
        """Sorgu başarısız olduğunda tutarlı bir hata sonucu üretir."""
        return NormalizedIOCResult(
            source=self.name,
            ip=ip,
            is_malicious=None,
            raw_score=None,
            categories=(),
            last_seen=None,
            queried_at=queried_at,
            provider_error_code=error_code,
            provider_error_message=error_message,
            confidence=None,
        )


# ======================================================================
# CONCRETE PROVIDERS
# ======================================================================


class VirusTotalProvider(ThreatIntelProvider):
    """Sadece VirusTotal API'sini bilir (IP reputation, v3 endpoint)."""

    name: str = "VirusTotal"

    def _extract_provider_error(self, response: requests.Response) -> str:
        """VirusTotal v3 hata formatı: {"error": {"code": "...", "message": "..."}}"""
        try:
            payload = response.json()
            msg = _safe_get_json_key(payload, "error", "message")
            if msg:
                return msg
        except (ValueError, requests.exceptions.JSONDecodeError):
            pass
        return super()._extract_provider_error(response)

    def query(self, ip: str | IPAddressType) -> NormalizedIOCResult | None:
        queried_at = _utc_now()
        ip_str = str(ip)
        url = f"{config.VIRUSTOTAL_BASE_URL}/ip_addresses/{ip_str}"
        headers = {"x-apikey": self._api_key or ""}

        response, err_code, err_msg = self._execute_request("GET", url, headers=headers)
        if response is None:
            return self._build_error_result(
                ip_str,
                err_code or ProviderErrorCode.REQUEST_ERROR,
                err_msg or "İstek başarısız oldu.",
                queried_at,
            )

        try:
            payload = response.json()
            data = payload.get("data", {})
            attributes = data.get("attributes", {})

            stats = attributes.get("last_analysis_stats", {})
            malicious_count = _safe_int(stats.get("malicious"), default=0) or 0

            last_analysis_results = attributes.get("last_analysis_results", {})
            flagged_engines = [
                engine
                for engine, verdict in last_analysis_results.items()
                if isinstance(verdict, dict) and verdict.get("category") == "malicious"
            ]

            confidence = _calculate_vt_confidence(stats)

            return NormalizedIOCResult(
                source=self.name,
                ip=ip_str,
                is_malicious=malicious_count > 0,
                raw_score=malicious_count,
                categories=tuple(sorted(flagged_engines)),
                last_seen=_parse_unix_timestamp(attributes.get("last_analysis_date")),
                queried_at=queried_at,
                provider_error_code=None,
                provider_error_message=None,
                confidence=confidence,
            )
        except (ValueError, TypeError, requests.exceptions.JSONDecodeError) as exc:
            self._log_warning("Yanıt ayrıştırılamadı: %s", exc)
            return self._build_error_result(
                ip_str,
                ProviderErrorCode.PARSE_ERROR,
                f"JSON parse error: {exc}",
                queried_at,
            )


class AbuseIPDBProvider(ThreatIntelProvider):
    """Sadece AbuseIPDB API'sini bilir (IP check endpoint)."""

    name: str = "AbuseIPDB"

    def _extract_provider_error(self, response: requests.Response) -> str:
        """AbuseIPDB hata formatı: {"errors": [{"detail": "...", "status": 401}]}"""
        try:
            payload = response.json()
            if isinstance(payload, dict) and "errors" in payload:
                errors = payload["errors"]
                if isinstance(errors, list) and errors:
                    extracted = [
                        str(err["detail"])
                        for err in errors
                        if isinstance(err, dict) and "detail" in err
                    ]
                    if extracted:
                        return " / ".join(extracted)
        except (ValueError, requests.exceptions.JSONDecodeError):
            pass
        return super()._extract_provider_error(response)

    def query(self, ip: str | IPAddressType) -> NormalizedIOCResult | None:
        queried_at = _utc_now()
        ip_str = str(ip)
        url = f"{config.ABUSEIPDB_BASE_URL}/check"
        headers = {
            "Key": self._api_key or "",
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip_str,
            "maxAgeInDays": config.ABUSEIPDB_MAX_AGE_DAYS,
        }

        response, err_code, err_msg = self._execute_request("GET", url, headers=headers, params=params)
        if response is None:
            return self._build_error_result(
                ip_str,
                err_code or ProviderErrorCode.REQUEST_ERROR,
                err_msg or "İstek başarısız oldu.",
                queried_at,
            )

        try:
            payload = response.json()
            data = payload.get("data", {})

            abuse_score = _safe_int(data.get("abuseConfidenceScore"), default=0) or 0

            categories: list[str] = []

            confidence = (
                round(abuse_score / 100, 4)
                if 0 <= abuse_score <= 100
                else None
            )

            return NormalizedIOCResult(
                source=self.name,
                ip=ip_str,
                is_malicious=abuse_score > 0,
                raw_score=abuse_score,
                categories=tuple(categories),
                last_seen=_parse_iso8601(data.get("lastReportedAt")),
                queried_at=queried_at,
                provider_error_code=None,
                provider_error_message=None,
                confidence=confidence,
            )
        except (ValueError, TypeError, requests.exceptions.JSONDecodeError) as exc:
            self._log_warning("Yanıt ayrıştırılamadı: %s", exc)
            return self._build_error_result(
                ip_str,
                ProviderErrorCode.PARSE_ERROR,
                f"JSON parse error: {exc}",
                queried_at,
            )


class AlienVaultOTXProvider(ThreatIntelProvider):
    """Sadece AlienVault OTX API'sini bilir (IPv4/IPv6 general endpoint)."""

    name: str = "AlienVault OTX"

    def _extract_provider_error(self, response: requests.Response) -> str:
        """AlienVault OTX hata formatı: {"detail": "..."} veya {"message": "..."}"""
        try:
            payload = response.json()
            err_msg = _safe_get_json_key(payload, "detail") or _safe_get_json_key(payload, "message")
            if err_msg:
                return err_msg
        except (ValueError, requests.exceptions.JSONDecodeError):
            pass
        return super()._extract_provider_error(response)

    def query(self, ip: str | IPAddressType) -> NormalizedIOCResult | None:
        queried_at = _utc_now()
        ip_obj = ip if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(ip)
        ip_version = "IPv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "IPv6"
        ip_str = str(ip_obj)

        url = f"{config.OTX_BASE_URL}/indicators/{ip_version}/{ip_str}/general"
        headers = {"X-OTX-API-KEY": self._api_key or ""}

        response, err_code, err_msg = self._execute_request("GET", url, headers=headers)
        if response is None:
            return self._build_error_result(
                ip_str,
                err_code or ProviderErrorCode.REQUEST_ERROR,
                err_msg or "İstek başarısız oldu.",
                queried_at,
            )

        try:
            payload = response.json()
            pulse_info = payload.get("pulse_info", {})
            pulse_count = _safe_int(pulse_info.get("count"), default=0) or 0
            pulses = pulse_info.get("pulses", []) or []

            tags: set[str] = set()
            latest_seen: datetime | None = None
            for pulse in pulses:
                if isinstance(pulse, dict):
                    for tag in pulse.get("tags", []):
                        tags.add(str(tag))
                    candidate = _parse_iso8601(pulse.get("modified") or pulse.get("created"))
                    if candidate and (latest_seen is None or candidate > latest_seen):
                        latest_seen = candidate

            categories = tuple(sorted(tags)[: config.OTX_MAX_CATEGORY_COUNT])

            return NormalizedIOCResult(
                source=self.name,
                ip=ip_str,
                is_malicious=pulse_count > 0,
                raw_score=pulse_count,
                categories=categories,
                last_seen=latest_seen,
                queried_at=queried_at,
                provider_error_code=None,
                provider_error_message=None,
                confidence=None,
            )
        except (ValueError, TypeError, requests.exceptions.JSONDecodeError) as exc:
            self._log_warning("Yanıt ayrıştırılamadı: %s", exc)
            return self._build_error_result(
                ip_str,
                ProviderErrorCode.PARSE_ERROR,
                f"JSON parse error: {exc}",
                queried_at,
            )


class URLHausProvider(ThreatIntelProvider):
    """Sadece URLHaus API'sini bilir (host endpoint)."""

    name: str = "URLHaus"

    def _extract_provider_error(self, response: requests.Response) -> str:
        """URLHaus özel hata ayrıştırıcısı: {"query_status": "...", "system_error": "..."}"""
        try:
            payload = response.json()
            if isinstance(payload, dict):
                system_error = payload.get("system_error")
                query_status = payload.get("query_status")
                if system_error:
                    return f"{query_status or 'error'}: {system_error}"
                if query_status and query_status != "ok":
                    return f"status_{query_status}"
        except (ValueError, requests.exceptions.JSONDecodeError):
            pass
        return super()._extract_provider_error(response)

    def query(self, ip: str | IPAddressType) -> NormalizedIOCResult | None:
        queried_at = _utc_now()
        ip_str = str(ip)
        url = f"{config.URLHAUS_BASE_URL}/host/"
        data = {"host": ip_str}

        response, err_code, err_msg = self._execute_request("POST", url, data=data)
        if response is None:
            return self._build_error_result(
                ip_str,
                err_code or ProviderErrorCode.REQUEST_ERROR,
                err_msg or "İstek başarısız oldu.",
                queried_at,
            )

        try:
            payload = response.json()
            query_status = payload.get("query_status")

            if query_status == "no_results":
                return NormalizedIOCResult(
                    source=self.name,
                    ip=ip_str,
                    is_malicious=None,
                    raw_score=0,
                    categories=(),
                    last_seen=None,
                    queried_at=queried_at,
                    provider_error_code=None,
                    provider_error_message=None,
                    confidence=None,
                )

            if query_status != "ok":
                return self._build_error_result(
                    ip_str,
                    ProviderErrorCode.UNEXPECTED_STATUS,
                    f"URLHaus query_status: {query_status}",
                    queried_at,
                )

            urls = payload.get("urls", []) or []
            url_count = _safe_int(payload.get("url_count"), default=len(urls)) or 0

            threats: set[str] = set()
            latest_seen: datetime | None = None
            for entry in urls:
                if isinstance(entry, dict):
                    threat = entry.get("threat")
                    if threat:
                        threats.add(str(threat))
                    candidate = _parse_urlhaus_datetime(entry.get("date_added"))
                    if candidate and (latest_seen is None or candidate > latest_seen):
                        latest_seen = candidate

            return NormalizedIOCResult(
                source=self.name,
                ip=ip_str,
                is_malicious=url_count > 0,
                raw_score=url_count,
                categories=tuple(sorted(threats)),
                last_seen=latest_seen,
                queried_at=queried_at,
                provider_error_code=None,
                provider_error_message=None,
                confidence=None,
            )
        except (ValueError, TypeError, requests.exceptions.JSONDecodeError) as exc:
            self._log_warning("Yanıt ayrıştırılamadı: %s", exc)
            return self._build_error_result(
                ip_str,
                ProviderErrorCode.PARSE_ERROR,
                f"JSON parse error: {exc}",
                queried_at,
            )


# ======================================================================
# SERVICE
# ======================================================================


class ThreatIntelService:
    """Provider'ları yönetir, IP'yi provider'lara gönderir, sonuçları toplar.

    Not: Metotlar ve veri yapıları thread-safe biçimde tasarlanmıştır. Gelecek
    sürümlerde provider sorguları ThreadPoolExecutor ile paralel hale getirilebilir.
    """

    def __init__(self, providers: list[ThreatIntelProvider]) -> None:
        if not providers:
            raise ValueError("ThreatIntelService en az bir provider gerektirir.")
        self._providers = providers
        self._cache: dict[str, list[NormalizedIOCResult]] = {}

    def enrich(self, ip: str) -> list[NormalizedIOCResult]:
        """Verilen IP'yi tüm yapılandırılmış provider'lara sorgular (Cache destekli)."""
        validated_ip = self._validate_ip(ip)
        ip_str = str(validated_ip)

        # 4. İyileştirme: Önbellekte varsa doğrudan döndür (Mükerrer sorgu önleme)
        if ip_str in self._cache:
            logger.debug("Önbellekten döndürülüyor: %s", ip_str)
            return self._cache[ip_str]

        results: list[NormalizedIOCResult] = []

        for provider in self._providers:
            if not provider.is_configured():
                logger.warning(
                    "[%s] API anahtarı yapılandırılmamış, atlanıyor.",
                    provider.name,
                )
                continue

            try:
                result = provider.query(validated_ip)
                if result is not None:
                    results.append(result)
            except Exception as exc:
                logger.exception(
                    "[%s] Provider sorgusu sırasında beklenmeyen hata oluştu.",
                    provider.name,
                )
                results.append(
                    NormalizedIOCResult(
                        source=provider.name,
                        ip=ip_str,
                        is_malicious=None,
                        raw_score=None,
                        categories=(),
                        last_seen=None,
                        queried_at=_utc_now(),
                        provider_error_code=ProviderErrorCode.UNKNOWN_ERROR,
                        provider_error_message=f"Unexpected error: {exc}",
                        confidence=None,
                    )
                )

        self._cache[ip_str] = results
        return results

    def enrich_findings_only(self, findings: list[Any]) -> dict[str, list[NormalizedIOCResult]]:
        """5. İyileştirme: Sadece bulgularda geçen (saldırgan/şüpheli) IP adreslerini hedefler."""
        target_ips: set[str] = set()

        for finding in findings:
            # Bulgu nesnesinde tanımlı IP attributes okunur (src_ip, dst_ip, ip, target_ip vb.)
            for attr in ("src_ip", "dst_ip", "ip", "target_ip", "source_ip"):
                val = getattr(finding, attr, None)
                if val and isinstance(val, str):
                    try:
                        if ipaddress.ip_address(val).is_global:
                            target_ips.add(val)
                    except ValueError:
                        pass

        logger.info("Bulgulardan tespit edilen %d adet public IP sorgulanıyor...", len(target_ips))
        return {ip: self.enrich(ip) for ip in target_ips}

    @staticmethod
    def _validate_ip(ip: str) -> IPAddressType:
        """IP adresinin geçerli bir IPv4/IPv6 adresi olduğunu doğrular ve nesne olarak döner."""
        try:
            return ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ValueError(f"Geçersiz IP adresi: {ip!r}") from exc


# ======================================================================
# FACTORIES
# ======================================================================


def build_default_session(
    pool_connections: int | None = None,
    pool_maxsize: int | None = None,
    allowed_methods: tuple[str, ...] | None = None,
) -> requests.Session:
    """Exponential backoff'lu retry stratejisi mount edilmiş bir Session üretir."""
    actual_connections = pool_connections if pool_connections is not None else config.THREAT_INTEL_POOL_CONNECTIONS
    actual_maxsize = pool_maxsize if pool_maxsize is not None else config.THREAT_INTEL_POOL_MAXSIZE
    actual_methods = allowed_methods if allowed_methods is not None else config.THREAT_INTEL_ALLOWED_METHODS

    max_retries = config.THREAT_INTEL_MAX_RETRIES

    retry_strategy = Retry(
        total=max_retries,
        connect=max_retries,
        read=max_retries,
        status=max_retries,
        backoff_factor=config.THREAT_INTEL_BACKOFF_FACTOR_SECONDS,
        status_forcelist=config.THREAT_INTEL_RETRY_STATUS_CODES,
        allowed_methods=frozenset(actual_methods),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=actual_connections,
        pool_maxsize=actual_maxsize,
    )

    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def build_default_providers(session: requests.Session) -> list[ThreatIntelProvider]:
    """.env dosyasından okunan API anahtarlarıyla tüm provider'ları üretir."""
    return [
        VirusTotalProvider(session, os.getenv(config.VIRUSTOTAL_API_KEY_ENV)),
        AbuseIPDBProvider(session, os.getenv(config.ABUSEIPDB_API_KEY_ENV)),
        AlienVaultOTXProvider(session, os.getenv(config.OTX_API_KEY_ENV)),
        URLHausProvider(session, os.getenv(config.URLHAUS_API_KEY_ENV)),
    ]