from dotenv import load_dotenv

from modules.threat_intel import (
    ThreatIntelService,
    build_default_providers,
    build_default_session,
)


def main() -> None:
    load_dotenv()

    session = build_default_session()
    providers = build_default_providers(session)

    service = ThreatIntelService(providers)

    results = service.enrich("8.8.8.8")

    print("=" * 80)

    for result in results:
        print(f"Provider              : {result.source}")
        print(f"IP                    : {result.ip}")
        print(f"Malicious             : {result.is_malicious}")
        print(f"Raw Score             : {result.raw_score}")
        print(f"Confidence            : {result.confidence}")
        print(f"Categories            : {list(result.categories)}")
        print(f"Last Seen             : {result.last_seen}")
        print(f"Queried At            : {result.queried_at}")
        print(f"Provider Error Code   : {result.provider_error_code}")
        print(f"Provider Error Message: {result.provider_error_message}")
        print("-" * 80)


if __name__ == "__main__":
    main()