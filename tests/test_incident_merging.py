from database.models import (
    initialize_db,
    create_incident,
    save_alerts,
    get_alerts,
    link_alert_to_incident,
    add_incident_note,
    get_incident_notes,
    get_incidents,
    get_incident_alerts,
    merge_incidents
)


def test_merge_incidents_preserves_alerts_and_notes(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    source = create_incident(
        "source-001",
        "PowerShell activity",
        "medium",
        db_path=db_path
    )

    target = create_incident(
        "target-001",
        "Suspicious network activity",
        "high",
        db_path=db_path
    )

    save_alerts([
        {
            "fingerprint": "alert-001",
            "rule_id": "TL-002",
            "rule_name": "Encoded PowerShell",
            "severity": "medium",
            "evidence": []
        },
        {
            "fingerprint": "alert-002",
            "rule_id": "TL-003",
            "rule_name": "Malicious IP",
            "severity": "high",
            "evidence": []
        }
    ], db_path)

    alerts = get_alerts(db_path)

    link_alert_to_incident(
        source["id"], alerts[0]["id"], db_path
    )

    link_alert_to_incident(
        target["id"], alerts[1]["id"], db_path
    )

    add_incident_note(
        source["id"],
        "Initial PowerShell investigation.",
        db_path
    )

    merged = merge_incidents(
        source["id"],
        target["id"],
        db_path
    )

    assert merged["id"] == target["id"]
    assert merged["severity"] == "high"

    assert len(get_incident_alerts(target["id"], db_path)) == 2

    notes = get_incident_notes(target["id"], db_path)

    assert len(notes) == 1
    assert notes[0]["note"] == "Initial PowerShell investigation."

    incidents = get_incidents(db_path)

    assert len(incidents) == 1
    assert incidents[0]["id"] == target["id"]


def test_cannot_merge_incident_into_itself(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    incident = create_incident(
        "incident-001",
        "Test incident",
        "low",
        db_path=db_path
    )

    import pytest

    with pytest.raises(ValueError):
        merge_incidents(
            incident["id"],
            incident["id"],
            db_path
        )


def test_cannot_merge_nonexistent_incident(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    incident = create_incident(
        "incident-001",
        "Test incident",
        "low",
        db_path=db_path
    )

    import pytest

    with pytest.raises(ValueError):
        merge_incidents(
            999,
            incident["id"],
            db_path
        )