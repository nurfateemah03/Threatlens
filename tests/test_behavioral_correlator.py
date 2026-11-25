
import json
from pathlib import Path

import pytest

from correlation.behavioral_correlator import (
    find_behavioral_sequences,
)


DATASET_PATH = Path("sample_data/behavioral_sequence.jsonl")


@pytest.fixture
def events():
    """Load synthetic events and assign database-style IDs."""

    with DATASET_PATH.open("r", encoding="utf-8") as file:
        data = [
            json.loads(line)
            for line in file
            if line.strip()
        ]

    for event_id, event in enumerate(data, start=1):
        event["id"] = event_id

    return data


def test_detects_complete_behavioral_sequence(events):
    alerts = find_behavioral_sequences(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["rule_id"] == "TL-004"
    assert alert["severity"] == "critical"
    assert alert["username"] == "analyst"
    assert alert["source_ip"] == "192.0.2.55"
    assert alert["destination_ip"] == "198.51.100.25"

    assert len(alert["evidence"]) == 8

    assert alert["behavioral_context"]["sequence"] == [
        "repeated_failed_logins",
        "successful_login",
        "encoded_powershell",
        "outbound_network_connection",
    ]


def test_rejects_insufficient_failed_logins(events):
    failed_events = [
        event
        for event in events
        if event.get("status") == "failed"
    ]

    events.remove(failed_events[-1])

    alerts = find_behavioral_sequences(events)

    assert alerts == []


def test_rejects_sequence_without_successful_login(events):
    events[:] = [
        event
        for event in events
        if event.get("status") != "success"
    ]

    alerts = find_behavioral_sequences(events)

    assert alerts == []


def test_rejects_successful_login_before_last_failed_attempt(events):
    successful_login = next(
        event
        for event in events
        if event.get("status") == "success"
    )

    successful_login["timestamp"] = "2026-11-25T10:02:30Z"

    alerts = find_behavioral_sequences(events)

    assert alerts == []


def test_rejects_sequence_outside_sixty_minute_window(events):
    network_event = next(
        event
        for event in events
        if event["event_type"] == "network_connection"
    )

    network_event["timestamp"] = "2026-11-25T11:01:00Z"

    alerts = find_behavioral_sequences(events)

    assert alerts == []


def test_rejects_mismatched_powerShell_username(events):
    powershell_event = next(
        event
        for event in events
        if event["event_type"] == "process_execution"
    )

    powershell_event["username"] = "different_user"

    alerts = find_behavioral_sequences(events)

    assert alerts == []


def test_rejects_network_activity_on_different_host(events):
    network_event = next(
        event
        for event in events
        if event["event_type"] == "network_connection"
    )

    network_event["host"] = "WORKSTATION-OTHER"

    alerts = find_behavioral_sequences(events)

    assert alerts == []
