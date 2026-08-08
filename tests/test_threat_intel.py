"""
test_threat_intel.py - Threat Intelligence (IOC Enrichment) Unit Testleri

Bu suite hiçbir gerçek ağ isteği ATMAZ. Tüm HTTP katmanı ``unittest.mock``
ile sahtelenir (bkz. ``_FakeResponse`` / ``_fake_session``), böylece testler
hızlı, deterministik ve CI ortamında API anahtarı gerektirmeden çalışır.

Kapsam:
    - Saf ayrıştırma yardımcıları (_safe_int, _parse_iso8601, vb.)
    - Her provider için başarı yolu (provider'a özgü şema ayrıştırması)
    - Tüm provider'lar için ortak hata yolları (timeout / connection /
      HTTP 4xx-5xx / bozuk JSON) - parametrized
    - is_configured() davranışı (API key yoksa provider atlanır)
    - ThreatIntelService.enrich() orkestrasyonu
    - build_default_session / build_default_providers factory'leri
"""

from __future__ import annotations

import logging
from dataclasses import FrozenInstanceError
from datetime import UTC
from json import JSONDecodeError
from unittest.mock import MagicMock

import pytest
import requests

import config
from modules import threat_intel as ti
from modules.threat_intel import (
    AbuseIPDBProvider,
    AlienVaultOTXProvider,
    NormalizedIOCResult,
    ProviderErrorCode,
    ThreatIntelProvider,
    ThreatIntelService,
    VirusTotalProvider,
    build_default_providers,
    build_default_session,
)

# ======================================================================
# TEST DOUBLES
# ======================================================================


class _FakeResponse:
    """``requests.Response``'un testler için gereken minimal yüzeyi."""

    def __init__(
        self,
        json_data=None,
        status_code: int = 200,
        ok: bool | None = None,
        reason: str = "OK",
        raise_json_error: bool = False,
    ) -> None:
        self.status_code = status_code
        self.ok = ok if ok is not None else 200 <= status_code < 400
        self.reason = reason
        self._json_data = json_data
        self._raise_json_error = raise_json_error

    def json(self):
        if self._raise_json_error:
            raise JSONDecodeError("bozuk json", "", 0)
        return self._json_data


def _fake_session(response: _FakeResponse | None = None, side_effect=None) -> MagicMock:
    """``.request()`` metodu sahtelenmiş bir Session mock'u üretir."""
    session = MagicMock(spec=requests.Session)
    if side_effect is not None:
        session.request.side_effect = side_effect
    else:
        session.request.return_value = response
    return session


PROVIDER_CLASSES: tuple[type[ThreatIntelProvider], ...] = (
    VirusTotalProvider,
    AbuseIPDBProvider,
    AlienVaultOTXProvider,
)


# ======================================================================
# SAF AYRIŞTIRMA YARDIMCILARI
# ======================================================================


def test_safe_int_valid_and_invalid():
    assert ti._safe_int("42") == 42
    assert ti._safe_int(42.9) == 42
    assert ti._safe_int(None, default=7) == 7
    assert ti._safe_int("not-a-number", default=-1) == -1


def test_parse_unix_timestamp_valid_and_invalid():
    dt = ti._parse_unix_timestamp(1700000000)
    assert dt is not None
    assert dt.tzinfo == UTC

    assert ti._parse_unix_timestamp(None) is None
    assert ti._parse_unix_timestamp("not-a-timestamp") is None


def test_parse_iso8601_valid_and_invalid():
    dt = ti._parse_iso8601("2026-01-15T10:00:00Z")
    assert dt is not None
    assert dt.year == 2026

    assert ti._parse_iso8601(None) is None
    assert ti._parse_iso8601("clearly not a date") is None


def test_calculate_vt_confidence():
    stats = {"malicious": 5, "suspicious": 2, "harmless": 10, "undetected": 3}
    confidence = ti._calculate_vt_confidence(stats)
    assert confidence == pytest.approx(7 / 20)

    assert ti._calculate_vt_confidence({}) is None
    assert ti._calculate_vt_confidence(
        {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
    ) is None


# ======================================================================
# is_configured()
# ======================================================================


@pytest.mark.parametrize("provider_cls", PROVIDER_CLASSES)
def test_provider_not_configured_without_api_key(provider_cls):
    provider = provider_cls(_fake_session(), api_key=None)
    assert provider.is_configured() is False


@pytest.mark.parametrize("provider_cls", PROVIDER_CLASSES)
def test_provider_configured_with_api_key(provider_cls):
    provider = provider_cls(_fake_session(), api_key="dummy-key")
    assert provider.is_configured() is True


# ======================================================================
# PROVIDER'A ÖZGÜ BAŞARI YOLLARI
# ======================================================================


def test_virustotal_query_success_malicious():
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 3,
                    "suspicious": 1,
                    "harmless": 60,
                    "undetected": 10,
                },
                "last_analysis_results": {
                    "EngineA": {"category": "malicious"},
                    "EngineB": {"category": "harmless"},
                    "EngineC": {"category": "malicious"},
                },
                "last_analysis_date": 1700000000,
            }
        }
    }
    session = _fake_session(_FakeResponse(json_data=payload))
    provider = VirusTotalProvider(session, api_key="vt-key")

    result = provider.query("1.2.3.4")

    assert isinstance(result, NormalizedIOCResult)
    assert result.source == VirusTotalProvider.name
    assert result.is_malicious is True
    assert result.raw_score == 3
    assert result.categories == ("EngineA", "EngineC")
    assert result.provider_error_code is None
    assert result.last_seen is not None

    # Immutability (frozen instance) kontrolü
    with pytest.raises(FrozenInstanceError):
        result.source = "altered-source"

    # x-apikey header'ının gerçekten gönderildiğini doğrula
    _, kwargs = session.request.call_args
    assert kwargs["headers"]["x-apikey"] == "vt-key"


def test_virustotal_query_success_clean():
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 5,
                },
                "last_analysis_results": {},
            }
        }
    }
    session = _fake_session(_FakeResponse(json_data=payload))
    provider = VirusTotalProvider(session, api_key="vt-key")

    result = provider.query("8.8.8.8")

    assert result.is_malicious is False
    assert result.raw_score == 0
    assert result.categories == ()


def test_abuseipdb_query_success_malicious():
    payload = {
        "data": {
            "abuseConfidenceScore": 87,
            "lastReportedAt": "2026-01-10T12:00:00Z",
        }
    }
    session = _fake_session(_FakeResponse(json_data=payload))
    provider = AbuseIPDBProvider(session, api_key="abuse-key")

    result = provider.query("5.6.7.8")

    assert result.source == AbuseIPDBProvider.name
    assert result.is_malicious is True
    assert result.raw_score == 87
    assert result.confidence == pytest.approx(0.87)
    assert result.last_seen is not None

    _, kwargs = session.request.call_args
    assert kwargs["headers"]["Key"] == "abuse-key"
    assert kwargs["params"]["ipAddress"] == "5.6.7.8"


def test_abuseipdb_query_success_clean():
    payload = {"data": {"abuseConfidenceScore": 0, "lastReportedAt": None}}
    session = _fake_session(_FakeResponse(json_data=payload))
    provider = AbuseIPDBProvider(session, api_key="abuse-key")

    result = provider.query("9.9.9.9")

    assert result.is_malicious is False
    assert result.raw_score == 0
    assert result.last_seen is None
    assert result.categories == ()


def test_abuseipdb_query_requests_verbose_and_extracts_categories():
    """AbuseIPDB, 'verbose' parametresi olmadan 'reports' listesini (ve
    dolayısıyla kategori bilgisini) döndürmez; provider bu parametreyi
    göndermeli ve gelen sayısal kategori kodlarını (bkz.
    config.ABUSEIPDB_CATEGORY_MAP) insan tarafından okunabilir etiketlere
    çevirmelidir. Haritada olmayan bir kod (999) da kaybolmadan
    "UNKNOWN_999" olarak korunmalıdır."""
    payload = {
        "data": {
            "abuseConfidenceScore": 100,
            "lastReportedAt": "2026-01-10T12:00:00Z",
            "reports": [
                {"categories": [18, 22], "comment": "SSH brute-force"},
                {"categories": [14, 999], "comment": "Port scan + bilinmeyen kod"},
            ],
        }
    }
    session = _fake_session(_FakeResponse(json_data=payload))
    provider = AbuseIPDBProvider(session, api_key="abuse-key")

    result = provider.query("6.6.6.6")

    assert result.categories == ("Port Scan", "Brute-Force", "SSH", "UNKNOWN_999")

    _, kwargs = session.request.call_args
    assert "verbose" in kwargs["params"]


def test_alienvault_otx_query_success_with_pulses():
    payload = {
        "pulse_info": {
            "count": config.OTX_MALICIOUS_PULSE_THRESHOLD,
            "pulses": [
                {"tags": ["botnet", "c2"], "modified": "2026-01-05T00:00:00Z"},
                {"tags": ["scanner"], "created": "2026-01-01T00:00:00Z"},
            ],
        }
    }
    session = _fake_session(_FakeResponse(json_data=payload))
    provider = AlienVaultOTXProvider(session, api_key="otx-key")

    result = provider.query("1.1.1.1")

    assert result.source == AlienVaultOTXProvider.name
    assert result.is_malicious is True
    assert result.raw_score == config.OTX_MALICIOUS_PULSE_THRESHOLD
    assert set(result.categories) == {"botnet", "c2", "scanner"}
    assert result.last_seen is not None


# ======================================================================
# "ZARARLI" HÜKMÜ EŞİKLERİ
# ======================================================================
# Üç sağlayıcının da ölçütü eskiden "sıfırdan büyük"tü. Gerçek bir capture
# üzerinde ölçüldü: GitHub Pages (185.199.111.153) raporda "ZARARLI -- yanıt
# veren 3 sağlayıcının tamamı zararlı dedi" damgası alıyordu, çünkü
# VirusTotal'de ~94 motordan 2'si işaretlemişti ve AbuseIPDB skoru 55'ti.
# Tek bir düşük kaliteli motorun işaretini "zararlı" ilan etmek, adli raporda
# "yanıt verememeyi temiz saymak" kadar zararlıdır.


def test_virustotal_below_engine_threshold_is_not_malicious():
    """1-2 motor, CDN adreslerinde rutin yanlış pozitiftir -- hüküm verilmemeli."""
    below = config.VIRUSTOTAL_MALICIOUS_ENGINE_THRESHOLD - 1
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": below, "suspicious": 0,
                                        "harmless": 90, "undetected": 2},
                "last_analysis_results": {
                    f"Engine{n}": {"category": "malicious"} for n in range(below)
                },
            }
        }
    }
    provider = VirusTotalProvider(_fake_session(_FakeResponse(json_data=payload)), api_key="k")

    result = provider.query("1.2.3.4")

    assert result.is_malicious is False
    # Kanıt GİZLENMEZ: ham skor korunur, analist kendi kararını verebilir.
    assert result.raw_score == below


def test_virustotal_at_engine_threshold_is_malicious():
    at = config.VIRUSTOTAL_MALICIOUS_ENGINE_THRESHOLD
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": at, "suspicious": 0,
                                        "harmless": 90, "undetected": 2},
                "last_analysis_results": {
                    f"Engine{n}": {"category": "malicious"} for n in range(at)
                },
            }
        }
    }
    provider = VirusTotalProvider(_fake_session(_FakeResponse(json_data=payload)), api_key="k")

    assert provider.query("1.2.3.4").is_malicious is True


def test_abuseipdb_below_score_threshold_is_not_malicious():
    """AbuseIPDB'nin kendi dokümantasyonu 25 altını düşük güven sayar."""
    below = config.ABUSEIPDB_MALICIOUS_SCORE_THRESHOLD - 1
    payload = {"data": {"abuseConfidenceScore": below}}
    provider = AbuseIPDBProvider(_fake_session(_FakeResponse(json_data=payload)), api_key="k")

    result = provider.query("1.2.3.4")

    assert result.is_malicious is False
    assert result.raw_score == below


def test_abuseipdb_at_score_threshold_is_malicious():
    at = config.ABUSEIPDB_MALICIOUS_SCORE_THRESHOLD
    payload = {"data": {"abuseConfidenceScore": at}}
    provider = AbuseIPDBProvider(_fake_session(_FakeResponse(json_data=payload)), api_key="k")

    assert provider.query("1.2.3.4").is_malicious is True


def test_otx_below_pulse_threshold_is_not_malicious():
    """Pulse'lar araştırma derlemelerini de içerir; tek pulse kanıt değildir."""
    below = config.OTX_MALICIOUS_PULSE_THRESHOLD - 1
    payload = {"pulse_info": {"count": below, "pulses": [{"tags": ["research"]}]}}
    provider = AlienVaultOTXProvider(_fake_session(_FakeResponse(json_data=payload)), api_key="k")

    result = provider.query("1.2.3.4")

    assert result.is_malicious is False
    assert result.raw_score == below


def test_alienvault_otx_query_success_no_pulses():
    payload = {"pulse_info": {"count": 0, "pulses": []}}
    session = _fake_session(_FakeResponse(json_data=payload))
    provider = AlienVaultOTXProvider(session, api_key="otx-key")

    result = provider.query("1.1.1.1")

    assert result.is_malicious is False
    assert result.raw_score == 0
    assert result.categories == ()


# ======================================================================
# ORTAK HATA YOLLARI (tüm provider'lar için parametrized)
# ======================================================================


@pytest.mark.parametrize("provider_cls", PROVIDER_CLASSES)
def test_query_handles_timeout(provider_cls):
    session = _fake_session(side_effect=requests.exceptions.Timeout("Connection timed out"))
    provider = provider_cls(session, api_key="key")

    result = provider.query("1.2.3.4")

    assert result.provider_error_code == ProviderErrorCode.TIMEOUT
    assert result.is_malicious is None
    assert result.raw_score is None
    assert result.provider_error_message is not None
    assert "timeout" in result.provider_error_message.lower() or "timed out" in result.provider_error_message.lower()


@pytest.mark.parametrize("provider_cls", PROVIDER_CLASSES)
def test_query_handles_connection_error(provider_cls):
    session = _fake_session(side_effect=requests.exceptions.ConnectionError("Connection refused"))
    provider = provider_cls(session, api_key="key")

    result = provider.query("1.2.3.4")

    assert result.provider_error_code == ProviderErrorCode.CONNECTION_ERROR
    assert result.provider_error_message is not None
    assert "connection" in result.provider_error_message.lower()


@pytest.mark.parametrize("provider_cls", PROVIDER_CLASSES)
def test_query_handles_generic_request_exception(provider_cls):
    session = _fake_session(side_effect=requests.exceptions.RequestException("boom"))
    provider = provider_cls(session, api_key="key")

    result = provider.query("1.2.3.4")

    assert result.provider_error_code == ProviderErrorCode.REQUEST_ERROR
    assert result.provider_error_message is not None
    assert "boom" in result.provider_error_message.lower()


@pytest.mark.parametrize("provider_cls", PROVIDER_CLASSES)
def test_query_handles_http_error_status(provider_cls):
    response = _FakeResponse(
        json_data={"error": {"message": "Rate limit exceeded"}},
        status_code=429,
        ok=False,
        reason="Too Many Requests",
    )
    session = _fake_session(response)
    provider = provider_cls(session, api_key="key")

    result = provider.query("1.2.3.4")

    assert result.provider_error_code == ProviderErrorCode.HTTP_ERROR
    assert result.is_malicious is None
    assert result.provider_error_message is not None
    assert "429" in result.provider_error_message or "too many requests" in result.provider_error_message.lower()


@pytest.mark.parametrize("provider_cls", PROVIDER_CLASSES)
def test_query_handles_malformed_json(provider_cls):
    response = _FakeResponse(status_code=200, ok=True, raise_json_error=True)
    session = _fake_session(response)
    provider = provider_cls(session, api_key="key")

    result = provider.query("1.2.3.4")

    assert result.provider_error_code == ProviderErrorCode.PARSE_ERROR
    assert result.is_malicious is None
    assert result.provider_error_message is not None
    assert "json" in result.provider_error_message.lower() or "bozuk" in result.provider_error_message.lower()


@pytest.mark.parametrize("provider_cls", PROVIDER_CLASSES)
def test_query_handles_empty_json_response(provider_cls):
    """Provider'ların boş {} yanıt aldıklarında çökmeden güvenli davranması testi."""
    session = _fake_session(_FakeResponse(json_data={}))
    provider = provider_cls(session, api_key="key")

    result = provider.query("1.2.3.4")

    assert isinstance(result, NormalizedIOCResult)
    assert result.is_malicious is False or result.is_malicious is None


# ======================================================================
# THREAT INTEL SERVICE
# ======================================================================


def test_service_requires_at_least_one_provider():
    with pytest.raises(ValueError):
        ThreatIntelService(providers=[])


def test_service_enrich_skips_unconfigured_providers():
    configured = VirusTotalProvider(
        _fake_session(_FakeResponse(json_data={"data": {"attributes": {}}})),
        api_key="vt-key",
    )
    unconfigured = AbuseIPDBProvider(_fake_session(), api_key=None)

    service = ThreatIntelService([configured, unconfigured])
    results = service.enrich("1.2.3.4")

    assert len(results) == 1
    assert results[0].source == VirusTotalProvider.name


def test_service_warns_once_per_unconfigured_provider(caplog):
    """Anahtarsız sağlayıcı uyarısı IP başına değil, sağlayıcı başına bir kez basılmalı.

    Uyarı `enrich()` içinde olduğu için her sorguda yeniden tetikleniyordu:
    anahtarsız çalıştırılan, 100 genel IP içeren bir capture'da tek bir
    sağlayıcı için 100 satır uyarı üretiliyor ve zaman aşımı/HTTP hatası
    gibi GERÇEK uyarılar log içinde görünmez hale geliyordu.
    """
    unconfigured = AbuseIPDBProvider(_fake_session(), api_key=None)
    service = ThreatIntelService([unconfigured])

    with caplog.at_level(logging.WARNING):
        for ip in ("1.2.3.4", "5.6.7.8", "9.10.11.12"):
            service.enrich(ip)

    warnings = [r for r in caplog.records if "yapılandırılmamış" in r.getMessage()]
    assert len(warnings) == 1, f"3 IP sorgulandı, 1 uyarı bekleniyordu: {len(warnings)}"


def test_service_enrich_aggregates_all_configured_providers():
    vt = VirusTotalProvider(
        _fake_session(_FakeResponse(json_data={"data": {"attributes": {}}})),
        api_key="vt-key",
    )
    abuse = AbuseIPDBProvider(
        _fake_session(_FakeResponse(json_data={"data": {"abuseConfidenceScore": 0}})),
        api_key="abuse-key",
    )

    service = ThreatIntelService([vt, abuse])
    results = service.enrich("8.8.8.8")

    sources = {r.source for r in results}
    assert sources == {VirusTotalProvider.name, AbuseIPDBProvider.name}


def test_service_enrich_rejects_invalid_ip():
    provider = VirusTotalProvider(_fake_session(), api_key="vt-key")
    service = ThreatIntelService([provider])

    with pytest.raises(ValueError):
        service.enrich("not-an-ip-address")


def test_service_enrich_accepts_ipv6():
    session = _fake_session(_FakeResponse(json_data={"data": {"attributes": {}}}))
    provider = VirusTotalProvider(session, api_key="vt-key")
    service = ThreatIntelService([provider])

    results = service.enrich("2001:4860:4860::8888")

    assert len(results) == 1
    assert results[0].ip == "2001:4860:4860::8888"


def test_service_handles_provider_unexpected_exception():
    """Provider sorgu sırasında beklenmeyen bir Python hatası verirse servis çökmeyip yakalamalı."""
    faulty_provider = VirusTotalProvider(_fake_session(), api_key="vt-key")
    faulty_provider.query = MagicMock(side_effect=KeyError("Ayrıştırma hatası"))

    service = ThreatIntelService([faulty_provider])
    results = service.enrich("1.2.3.4")

    assert len(results) == 1
    assert results[0].provider_error_code in (
        ProviderErrorCode.UNKNOWN_ERROR,
        ProviderErrorCode.PARSE_ERROR,
    )


def test_service_enrich_handles_duplicate_providers():
    """Aynı provider servise birden fazla kez geçildiğinde orkestrasyonun stabil çalışması."""
    session = _fake_session(_FakeResponse(json_data={"data": {"attributes": {}}}))
    vt1 = VirusTotalProvider(session, api_key="vt-key")
    vt2 = VirusTotalProvider(session, api_key="vt-key")

    service = ThreatIntelService([vt1, vt2])
    results = service.enrich("1.1.1.1")

    assert len(results) == 2
    assert all(r.source == VirusTotalProvider.name for r in results)


# ======================================================================
# FACTORIES
# ======================================================================


def test_build_default_session_mounts_retry_adapter():
    session = build_default_session()
    try:
        assert isinstance(session, requests.Session)
        https_adapter = session.get_adapter("https://example.com")
        assert https_adapter.max_retries.total == ti.config.THREAT_INTEL_MAX_RETRIES
    finally:
        session.close()


def test_build_default_providers_reads_env_vars(monkeypatch):
    monkeypatch.setenv(ti.config.VIRUSTOTAL_API_KEY_ENV, "vt-secret")
    monkeypatch.delenv(ti.config.ABUSEIPDB_API_KEY_ENV, raising=False)
    monkeypatch.delenv(ti.config.OTX_API_KEY_ENV, raising=False)

    session = _fake_session()
    providers = build_default_providers(session)

    assert len(providers) == 3

    # Sıralamadan bağımsız provider seti kontrolü
    expected_names = {
        VirusTotalProvider.name,
        AbuseIPDBProvider.name,
        AlienVaultOTXProvider.name,
    }
    provider_by_name = {p.name: p for p in providers}
    assert set(provider_by_name.keys()) == expected_names

    assert provider_by_name[VirusTotalProvider.name].is_configured() is True
    assert provider_by_name[AbuseIPDBProvider.name].is_configured() is False
    assert provider_by_name[AlienVaultOTXProvider.name].is_configured() is False
