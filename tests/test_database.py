
import json

from database.models import (
    initialize_db,
    insert_events,
    get_events,
    get_event_count
)


def sample_event():

    return {
        "timestamp": "2026-11-14T10:30:00Z",
        "event_type": "authentication",
        "source": "windows",
        "host": "WORKSTATION-01",
        "username": "admin",
        "source_ip": "192.0.2.15",
        "destination_ip": None,
        "process": None,
        "command_line": None,
        "status": "failed",
        "raw_event": {
            "timestamp": "2026-11-14T10:30:00Z",
            "event_type": "authentication",
            "user": "admin"
        }
    }


def test_database_initialization(tmp_path):

    db_path = tmp_path / "test.db"

    initialize_db(db_path)

    assert db_path.exists()


def test_insert_event(tmp_path):

    db_path = tmp_path / "test.db"

    initialize_db(db_path)

    count = insert_events(
        [sample_event()],
        db_path
    )

    assert count == 1
    assert get_event_count(db_path) == 1


def test_retrieve_event(tmp_path):

    db_path = tmp_path / "test.db"

    initialize_db(db_path)
    insert_events([sample_event()], db_path)

    events = get_events(db_path)

    assert len(events) == 1
    assert events[0]["username"] == "admin"


def test_raw_event_preserved(tmp_path):

    db_path = tmp_path / "test.db"

    initialize_db(db_path)
    insert_events([sample_event()], db_path)

    events = get_events(db_path)

    original = json.loads(events[0]["raw_event"])

    assert original["user"] == "admin"



def test_insert_multiple_events(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    events = []

    for i in range(3):
        event = sample_event()
        event["timestamp"] = f"2026-11-14T10:0{i}:00Z"

        # Make the original raw event unique too
        raw_event = event.get("raw_event", event)
        event["raw_event"] = {
            **raw_event,
            "timestamp": f"2026-11-14T10:0{i}:00Z"
        }

        events.append(event)

    inserted = insert_events(events, db_path)

    assert inserted == 3
    assert get_event_count(db_path) == 3



def test_empty_insert(tmp_path):

    db_path = tmp_path / "test.db"

    initialize_db(db_path)

    assert insert_events([], db_path) == 0
    assert get_event_count(db_path) == 0


def test_prevents_duplicate_events(tmp_path):

    db_path = tmp_path / "test.db"

    initialize_db(db_path)

    event = sample_event()

    first_insert = insert_events([event], db_path)
    second_insert = insert_events([event], db_path)

    assert first_insert == 1
    assert second_insert == 0
    assert get_event_count(db_path) == 1
