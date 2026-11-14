
import pytest

from ingestion.parser import (
    parse_event,
    parse_jsonl,
    EventParsingError
)

from ingestion.normalizer import (
    normalize_event,
    normalize_timestamp,
    EventNormalizationError
)


def test_parse_valid_json():

    event = parse_event(
        '{"event_type": "authentication"}'
    )

    assert event["event_type"] == "authentication"


def test_parse_invalid_json():

    with pytest.raises(EventParsingError):
        parse_event('{"event_type":')


def test_parse_jsonl():

    data = (
        '{"event_type": "authentication"}\n'
        '{"event_type": "process_execution"}'
    )

    events = parse_jsonl(data)

    assert len(events) == 2


def test_normalize_event():

    event = {
        "timestamp": "2026-11-14T10:30:00Z",
        "event_type": "AUTHENTICATION",
        "source": "WINDOWS",
        "host": "WORKSTATION-01",
        "user": "admin",
        "src_ip": "192.0.2.15",
        "status": "failed"
    }

    result = normalize_event(event)

    assert result["event_type"] == "authentication"
    assert result["source"] == "windows"
    assert result["username"] == "admin"
    assert result["source_ip"] == "192.0.2.15"
    assert result["destination_ip"] is None


def test_normalize_invalid_ip():

    event = {
        "timestamp": "2026-11-14T10:30:00Z",
        "event_type": "authentication",
        "source": "windows",
        "host": "WORKSTATION-01",
        "source_ip": "not-an-ip"
    }

    with pytest.raises(EventNormalizationError):
        normalize_event(event)


def test_normalize_missing_required_field():

    event = {
        "timestamp": "2026-11-14T10:30:00Z",
        "event_type": "authentication",
        "source": "windows"
    }

    with pytest.raises(EventNormalizationError):
        normalize_event(event)


def test_normalize_timestamp_to_utc():

    result = normalize_timestamp(
        "2026-11-14T13:30:00+03:00"
    )

    assert result == "2026-11-14T10:30:00Z"
