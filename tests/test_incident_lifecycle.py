import pytest

from database.models import (
    initialize_db,
    create_incident,
    update_incident_status
)


def create_test_incident(db_path):
    initialize_db(db_path)

    return create_incident(
        "lifecycle-test-001",
        "Suspicious authentication activity",
        "high",
        db_path=db_path
    )


def test_incident_can_be_marked_investigating(tmp_path):
    db_path = tmp_path / "test.db"
    incident = create_test_incident(db_path)

    updated = update_incident_status(
        incident["id"],
        "investigating",
        db_path
    )

    assert updated["status"] == "investigating"
    assert updated["resolved_at"] is None


def test_incident_can_be_resolved(tmp_path):
    db_path = tmp_path / "test.db"
    incident = create_test_incident(db_path)

    updated = update_incident_status(
        incident["id"],
        "resolved",
        db_path
    )

    assert updated["status"] == "resolved"
    assert updated["resolved_at"] is not None


def test_resolved_incident_can_be_reopened(tmp_path):
    db_path = tmp_path / "test.db"
    incident = create_test_incident(db_path)

    update_incident_status(
        incident["id"],
        "resolved",
        db_path
    )

    updated = update_incident_status(
        incident["id"],
        "investigating",
        db_path
    )

    assert updated["status"] == "investigating"
    assert updated["resolved_at"] is None


def test_invalid_status_is_rejected(tmp_path):
    db_path = tmp_path / "test.db"
    incident = create_test_incident(db_path)

    with pytest.raises(ValueError):
        update_incident_status(
            incident["id"],
            "pending",
            db_path
        )


def test_nonexistent_incident_is_rejected(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    with pytest.raises(ValueError):
        update_incident_status(
            999,
            "resolved",
            db_path
        )