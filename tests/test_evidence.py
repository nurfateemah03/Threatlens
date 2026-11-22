
import json

from database.models import (
    initialize_db,
    get_connection,
    insert_events,
    get_alert_evidence_events,
)


def test_alert_retrieves_original_evidence_events(tmp_path):

    db_path = tmp_path / "test_evidence.db"

    initialize_db(db_path)

    events = [
        {
            "timestamp": "2026-11-22T10:00:00Z",
            "event_type": "authentication",
            "source": "windows",
            "host": "WORKSTATION-01",
            "username": "analyst",
            "source_ip": "192.0.2.10",
            "destination_ip": None,
            "process": None,
            "command_line": None,
            "status": "failed",
            "raw_event": {
                "event": "failed_login",
                "timestamp": "2026-11-22T10:00:00Z"
            },
        },
        {
            "timestamp": "2026-11-22T10:01:00Z",
            "event_type": "authentication",
            "source": "windows",
            "host": "WORKSTATION-01",
            "username": "analyst",
            "source_ip": "192.0.2.10",
            "destination_ip": None,
            "process": None,
            "command_line": None,
            "status": "failed",
            "raw_event": {
                "event": "failed_login",
                "timestamp": "2026-11-22T10:01:00Z"
            },
        },
    ]

    insert_events(events, db_path)

    with get_connection(db_path) as connection:

        stored_events = connection.execute(
            "SELECT id FROM events ORDER BY id"
        ).fetchall()

        evidence_ids = [
            row["id"] for row in stored_events
        ]

        cursor = connection.execute(
            """
            INSERT INTO alerts (
                fingerprint,
                rule_id,
                rule_name,
                severity,
                description,
                evidence_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "test-fingerprint",
                "TL-001",
                "Brute Force Detection",
                "high",
                "Repeated failed authentication attempts",
                json.dumps(evidence_ids),
            )
        )

        alert_id = cursor.lastrowid

    evidence = get_alert_evidence_events(
        alert_id,
        db_path
    )

    assert len(evidence) == 2
    assert [event["id"] for event in evidence] == evidence_ids
    assert evidence[0]["event_type"] == "authentication"
    assert evidence[0]["username"] == "analyst"
    assert evidence[0]["source_ip"] == "192.0.2.10"


def test_missing_alert_returns_empty_evidence(tmp_path):

    db_path = tmp_path / "test_missing_evidence.db"

    initialize_db(db_path)

    evidence = get_alert_evidence_events(
        999,
        db_path
    )

    assert evidence == []


def test_alert_with_empty_evidence_returns_empty_list(tmp_path):

    db_path = tmp_path / "test_empty_evidence.db"

    initialize_db(db_path)

    with get_connection(db_path) as connection:

        cursor = connection.execute(
            """
            INSERT INTO alerts (
                fingerprint,
                rule_id,
                rule_name,
                severity,
                description,
                evidence_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "empty-evidence",
                "TL-001",
                "Test Rule",
                "low",
                "Test alert",
                "[]",
            )
        )

        alert_id = cursor.lastrowid

    evidence = get_alert_evidence_events(
        alert_id,
        db_path
    )

    assert evidence == []
