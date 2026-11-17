import pytest

from database.models import (
    initialize_db,
    create_incident,
    get_incidents,
    update_incident_priority,
)


def test_incident_priority_is_saved(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    incident = create_incident(
        fingerprint="test-scoring-001",
        title="Test incident",
        severity="high",
        db_path=db_path
    )

    updated = update_incident_priority(
        incident_id=incident["id"],
        priority_score=68,
        priority="high",
        db_path=db_path
    )

    assert updated["priority_score"] == 68
    assert updated["priority"] == "high"


def test_incident_priority_is_available_in_incident_list(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    incident = create_incident(
        fingerprint="test-scoring-002",
        title="Test incident",
        severity="medium",
        db_path=db_path
    )

    update_incident_priority(
        incident["id"],
        30,
        "medium",
        db_path
    )

    stored = get_incidents(db_path)[0]

    assert stored["priority_score"] == 30
    assert stored["priority"] == "medium"


def test_invalid_priority_is_rejected(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    incident = create_incident(
        fingerprint="test-scoring-003",
        title="Test incident",
        severity="low",
        db_path=db_path
    )

    with pytest.raises(ValueError):
        update_incident_priority(
            incident["id"],
            20,
            "urgent",
            db_path
        )


def test_score_above_90_is_rejected(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    incident = create_incident(
        fingerprint="test-scoring-004",
        title="Test incident",
        severity="low",
        db_path=db_path
    )

    with pytest.raises(ValueError):
        update_incident_priority(
            incident["id"],
            100,
            "critical",
            db_path
        )


def test_missing_incident_is_rejected(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    with pytest.raises(ValueError):
        update_incident_priority(
            999,
            20,
            "low",
            db_path
        )