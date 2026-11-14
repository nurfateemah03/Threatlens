
import json
from typing import Any


class EventParsingError(ValueError):
    """Raised when an incoming security event cannot be parsed."""


def parse_event(raw_event: str) -> dict[str, Any]:
    """
    Parse a JSON security event into a Python dictionary.
    """

    try:
        event = json.loads(raw_event)

    except json.JSONDecodeError as exc:
        raise EventParsingError(
            f"Invalid JSON: {exc}"
        ) from exc

    if not isinstance(event, dict):
        raise EventParsingError(
            "Security event must be a JSON object."
        )

    return event


def parse_jsonl(raw_data: str) -> list[dict[str, Any]]:
    """
    Parse multiple newline-delimited JSON security events.
    """

    events = []

    for line_number, line in enumerate(raw_data.splitlines(), start=1):

        if not line.strip():
            continue

        try:
            event = parse_event(line)
            events.append(event)

        except EventParsingError as exc:
            raise EventParsingError(
                f"Error on line {line_number}: {exc}"
            ) from exc

    return events
