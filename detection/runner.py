
from database.models import (
    DEFAULT_DB_PATH,
    initialize_db,
    get_events,
    save_alerts,
    get_alerts,
    get_incidents,
    get_incident_alerts,
    update_incident_priority,
)

from detection.engine import run_detection_engine
from enrichment.enricher import enrich_alert
from enrichment.provider_manager import enrich_indicator
from correlation.correlator import correlate_alert
from intelligence.scoring import calculate_incident_score

def get_alert_indicator(alert):
    """
    Select the most relevant indicator for external enrichment.

    Prioritize destination IPs, then domains, file hashes,
    and finally source IPs.
    """

    candidates = [
        ("destination_ip", "ip"),
        ("domain", "domain"),
        ("file_hash", "file_hash"),
        ("source_ip", "ip")
    ]

    for field, indicator_type in candidates:
        value = alert.get(field)

        if value:
            return value, indicator_type

    return None, None


def run_detection(db_path=DEFAULT_DB_PATH):
    initialize_db(db_path)

    events = get_events(db_path)

    alerts = run_detection_engine(events)

    enriched_alerts = []

    for alert in alerts:
        # Existing local IOC enrichment
        alert = enrich_alert(alert)

        # External threat intelligence
        indicator, indicator_type = get_alert_indicator(alert)

        if indicator:
            alert["external_intelligence"] = enrich_indicator(
                indicator,
                indicator_type,
                db_path
            )
        else:
            alert["external_intelligence"] = None

        enriched_alerts.append(alert)

    save_alerts(enriched_alerts, db_path)

    # Retrieve persisted alerts so each one has a database ID.
    stored_alerts = get_alerts(db_path)

    # First, correlate alerts into incidents.
    for alert in stored_alerts:
        correlate_alert(alert, db_path)

    # Then calculate and persist the score for every incident.
    incidents = get_incidents(db_path)

    for incident in incidents:
        incident_alerts = get_incident_alerts(
            incident["id"],
            db_path
        )

        scoring_result = calculate_incident_score(incident_alerts)

        update_incident_priority(
            incident_id=incident["id"],
            priority_score=scoring_result["score"],
            priority=scoring_result["priority"],
            db_path=db_path
        )

    return get_alerts(db_path)