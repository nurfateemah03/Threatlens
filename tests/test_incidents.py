from database.models import (
    initialize_db,
    create_incident,
    link_alert_to_incident,
    add_incident_note,
    get_incident_notes,
    get_incidents,
    save_alerts
)


def test_create_incident(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    incident = create_incident(
        "fingerprint-001",
        "Suspicious activity",
        "high",
        db_path=db_path
    )

    assert incident["title"] == "Suspicious activity"
    assert incident["severity"] == "high"
    assert incident["status"] == "open"


def test_duplicate_incident_is_not_created(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    first = create_incident(
        "fingerprint-001",
        "Suspicious activity",
        "high",
        db_path=db_path
    )

    second = create_incident(
        "fingerprint-001",
        "Suspicious activity",
        "high",
        db_path=db_path
    )

    assert first["id"] == second["id"]
    assert len(get_incidents(db_path)) == 1


def test_add_and_retrieve_incident_notes(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    incident = create_incident(
        "fingerprint-001",
        "Suspicious activity",
        "high",
        db_path=db_path
    )

    add_incident_note(
        incident["id"],
        "Investigating suspicious login activity.",
        db_path
    )

    notes = get_incident_notes(incident["id"], db_path)

    assert len(notes) == 1
    assert notes[0]["note"] == "Investigating suspicious login activity."


def test_incident_alert_linking(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    incident = create_incident(
        "fingerprint-001",
        "Suspicious activity",
        "high",
        db_path=db_path
    )

    alert = {
        "fingerprint": "alert-001",
        "rule_id": "TL-003",
        "rule_name": "Malicious IP",
        "severity": "high",
        "evidence": []
    }

    save_alerts([alert], db_path)

    from database.models import get_alerts
    saved_alert = get_alerts(db_path)[0]

    link_alert_to_incident(
        incident["id"],
        saved_alert["id"],
        db_path
    )

    incidents = get_incidents(db_path)

    assert incidents[0]["alert_count"] == 1