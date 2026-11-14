from database.models import (
    DEFAULT_DB_PATH,
    initialize_db,
    get_events,
    save_alerts,
    get_alerts
)

from detection.engine import run_detection_engine
from enrichment.enricher import enrich_alert


def run_detection(db_path=DEFAULT_DB_PATH):
    initialize_db(db_path)

    events = get_events(db_path)

    alerts = run_detection_engine(events)

    enriched_alerts = [
        enrich_alert(alert)
        for alert in alerts
    ]

    save_alerts(enriched_alerts, db_path)

    return get_alerts(db_path)