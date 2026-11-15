from database.models import get_connection
import pytest

from database.models import (
    initialize_db,
    save_alerts,
    get_alerts,
    get_incidents,
    get_incident_alerts,
)

from correlation.correlator import correlate_alert


def store_test_alert(db_path, fingerprint, username, source_ip, destination_ip=None):
    save_alerts([{
        "rule_id": fingerprint,
        "rule_name": "Test security alert",
        "severity": "medium",
        "username": username,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "evidence": []
    }], db_path)

    saved_alerts = get_alerts(db_path)

    return next(
        alert for alert in saved_alerts
        if alert["rule_id"] == fingerprint
    )


def test_alert_creates_incident(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    alert = store_test_alert(
        db_path,
        "alert-001",
        "alice",
        "192.0.2.10"
    )

    incident = correlate_alert(alert, db_path)

    assert incident["status"] == "open"
    assert len(get_incidents(db_path)) == 1
    assert len(get_incident_alerts(incident["id"], db_path)) == 1


def test_related_alerts_merge_into_existing_incident(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    first_alert = store_test_alert(
        db_path,
        "alert-001",
        "alice",
        "192.0.2.10",
        "198.51.100.20"
    )

    second_alert = store_test_alert(
        db_path,
        "alert-002",
        "alice",
        "192.0.2.10",
        "203.0.113.20"
    )

    first_incident = correlate_alert(first_alert, db_path)
    second_incident = correlate_alert(second_alert, db_path)

    assert first_incident["id"] == second_incident["id"]
    assert len(get_incidents(db_path)) == 1
    assert len(
        get_incident_alerts(first_incident["id"], db_path)
    ) == 2


def test_alerts_with_only_one_matching_field_do_not_merge(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    first_alert = store_test_alert(
        db_path,
        "alert-001",
        "alice",
        "192.0.2.10"
    )

    second_alert = store_test_alert(
        db_path,
        "alert-002",
        "alice",
        "192.0.2.20"
    )

    correlate_alert(first_alert, db_path)
    correlate_alert(second_alert, db_path)

    assert len(get_incidents(db_path)) == 2


def test_processing_same_alert_twice_does_not_duplicate_incident(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    alert = store_test_alert(
        db_path,
        "alert-001",
        "alice",
        "192.0.2.10"
    )

    first = correlate_alert(alert, db_path)
    second = correlate_alert(alert, db_path)

    assert first["id"] == second["id"]
    assert len(get_incidents(db_path)) == 1
    assert len(get_incident_alerts(first["id"], db_path)) == 1


def test_alert_without_persisted_id_is_rejected(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    with pytest.raises(ValueError):
        correlate_alert(
            {"fingerprint": "alert-001"},
            db_path
        )



def test_alerts_outside_time_window_do_not_merge(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    first_alert = store_test_alert(
        db_path,
        "alert-001",
        "alice",
        "192.0.2.10",
        "198.51.100.20"
    )

    # Move the first alert's timestamp well into the past.
    with get_connection(db_path) as connection:
        connection.execute(
            """
            UPDATE alerts
            SET created_at = ?
            WHERE id = ?
            """,
            ("2020-01-01 10:00:00", first_alert["id"])
        )

    first_alert["created_at"] = "2020-01-01 10:00:00"

    second_alert = store_test_alert(
        db_path,
        "alert-002",
        "alice",
        "192.0.2.10",
        "203.0.113.20"
    )

    correlate_alert(first_alert, db_path)
    correlate_alert(second_alert, db_path)

    assert len(get_incidents(db_path)) == 2