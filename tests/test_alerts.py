
from database.models import (
    initialize_db,
    save_alerts,
    get_alerts
)

from enrichment.enricher import enrich_alert


def test_alert_storage_and_duplicate_prevention(tmp_path):
    db_path = tmp_path / "alerts.db"
    initialize_db(db_path)

    alert = {
        "rule_id": "TL-003",
        "rule_name": "Connection to Known Malicious IP",
        "severity": "high",
        "description": "Test alert",
        "destination_ip": "198.51.100.25",
        "mitre_attack": {},
        "evidence": [1]
    }

    save_alerts([alert], db_path)
    save_alerts([alert], db_path)

    stored = get_alerts(db_path)

    assert len(stored) == 1
    assert stored[0]["rule_id"] == "TL-003"
    assert stored[0]["status"] == "open"
    assert stored[0]["evidence"] == [1]


def test_enriches_matching_ip():
    alert = {
        "destination_ip": "198.51.100.25"
    }

    enriched = enrich_alert(alert)

    assert enriched["threat_intelligence"]["matched"] is True
    assert (
        enriched["threat_intelligence"]["classification"]
        == "synthetic_test_indicator"
    )


def test_does_not_enrich_unmatched_ip():
    alert = {
        "destination_ip": "192.0.2.100"
    }

    enriched = enrich_alert(alert)

    assert enriched["threat_intelligence"]["matched"] is False
