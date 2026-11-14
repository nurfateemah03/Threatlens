
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any


class EventNormalizationError(ValueError):
    """Raised when an event cannot be normalized."""


# Map alternative field names to our standard schema.
FIELD_ALIASES = {
    "timestamp": ["timestamp", "@timestamp", "time"],
    "event_type": ["event_type", "event.action", "type"],
    "source": ["source", "log_source", "provider"],
    "host": ["host", "hostname", "computer_name"],
    "username": ["username", "user", "user.name"],
    "source_ip": ["source_ip", "src_ip", "source.address"],
    "destination_ip": [
        "destination_ip",
        "dest_ip",
        "destination.address"
    ],
    "process": ["process", "process_name", "process.name"],
    "command_line": [
        "command_line",
        "cmdline",
        "process.command_line"
    ],
    "status": ["status", "result", "outcome"]
}


REQUIRED_FIELDS = [
    "timestamp",
    "event_type",
    "source",
    "host"
]


def get_field(event: dict, field: str) -> Any:
    """Retrieve a field using its standard name or aliases."""

    for alias in FIELD_ALIASES[field]:
        if alias in event:
            return event[alias]

    return None


def normalize_timestamp(value: Any) -> str:
    """Convert timestamps into UTC ISO 8601 format."""

    if not isinstance(value, str) or not value.strip():
        raise EventNormalizationError(
            "Timestamp must be a non-empty string."
        )

    try:
        timestamp = datetime.fromisoformat(
            value.strip().replace("Z", "+00:00")
        )

    except ValueError as exc:
        raise EventNormalizationError(
            f"Invalid timestamp: {value}"
        ) from exc

    if timestamp.tzinfo is None:
        raise EventNormalizationError(
            "Timestamp must include a timezone."
        )

    return (
        timestamp
        .astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def normalize_ip(value: Any, field: str) -> str | None:
    """Validate and normalize an optional IP address."""

    if value is None or value == "":
        return None

    if not isinstance(value, str):
        raise EventNormalizationError(
            f"{field} must be a string."
        )

    try:
        return str(ip_address(value))

    except ValueError as exc:
        raise EventNormalizationError(
            f"Invalid IP address in {field}: {value}"
        ) from exc


def normalize_event(event: dict) -> dict:
    """
    Convert an incoming security event into
    the standard ThreatLens event schema.
    """

    if not isinstance(event, dict):
        raise EventNormalizationError(
            "Event must be a dictionary."
        )

    normalized = {
        field: get_field(event, field)
        for field in FIELD_ALIASES
    }

    # Check mandatory fields.
    for field in REQUIRED_FIELDS:

        value = normalized[field]

        if not isinstance(value, str) or not value.strip():
            raise EventNormalizationError(
                f"Missing or invalid required field: {field}"
            )

    # Standardize timestamps.
    normalized["timestamp"] = normalize_timestamp(
        normalized["timestamp"]
    )

    # Standardize event types.
    normalized["event_type"] = (
        normalized["event_type"].strip().lower()
    )

    # Normalize source and host.
    normalized["source"] = normalized["source"].strip().lower()
    normalized["host"] = normalized["host"].strip()

    # Validate optional IP addresses.
    normalized["source_ip"] = normalize_ip(
        normalized["source_ip"], "source_ip"
    )

    normalized["destination_ip"] = normalize_ip(
        normalized["destination_ip"], "destination_ip"
    )

    # Validate optional string fields.
    for field in [
        "username",
        "process",
        "command_line",
        "status"
    ]:
        value = normalized[field]

        if value is not None and not isinstance(value, str):
            raise EventNormalizationError(
                f"{field} must be a string or None."
            )

        if isinstance(value, str):
            normalized[field] = value.strip() or None

    return normalized
