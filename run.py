from ingestion.pipeline import ingest_file
from detection.runner import run_detection


if __name__ == "__main__":
    result = ingest_file("sample_data/events.jsonl")

    print("INGESTION RESULTS")
    print(result)

    alerts = run_detection()

    print("\nDETECTION RESULTS")
    print(f"Total alerts: {len(alerts)}")

    for alert in alerts:
        print(
            f"\n[{alert['severity'].upper()}] "
            f"{alert['rule_id']} - {alert['rule_name']}"
        )
        print(f"Evidence: {alert['evidence']}")
        print(f"Status: {alert['status']}")