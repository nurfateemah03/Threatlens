
from ingestion.pipeline import ingest_file
from database.models import get_events, get_event_count


def test_end_to_end_ingestion(tmp_path):

    sample_file = tmp_path / "events.jsonl"
    db_path = tmp_path / "threatlens_test.db"

    sample_file.write_text(
        '{"timestamp":"2026-11-14T10:30:00Z",'
        '"event_type":"authentication",'
        '"source":"windows",'
        '"host":"WORKSTATION-01",'
        '"username":"admin",'
        '"source_ip":"192.0.2.15",'
        '"status":"failed"}\n'
    )

    result = ingest_file(sample_file, db_path)

    assert result["events_received"] == 1
    assert result["events_normalized"] == 1
    assert result["events_stored"] == 1

    assert get_event_count(db_path) == 1

    events = get_events(db_path)

    assert events[0]["event_type"] == "authentication"
    assert events[0]["username"] == "admin"
