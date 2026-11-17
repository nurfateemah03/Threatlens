
from ingestion.pipeline import ingest_file
from detection.runner import run_detection
from database.models import get_incidents


if __name__ == "__main__":

    # Ingestion
    result = ingest_file("sample_data/events.jsonl")

    print("\nINGESTION RESULTS")
    print(result)

    # Detection
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

    # Incident results and calculated priorities
    incidents = get_incidents()

    print("\nINCIDENT RESULTS")
    print(f"Total incidents: {len(incidents)}")

    for incident in incidents:
        print(
            f"\n[{incident['priority'].upper()}] "
            f"Score: {incident['priority_score']}/90 | "
            f"{incident['title']} | "
            f"Status: {incident['status']} | "
            f"Alerts: {incident['alert_count']}"
        )
