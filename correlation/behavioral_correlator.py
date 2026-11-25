
from datetime import datetime, timedelta, timezone


RULE_ID = "TL-004"
RULE_NAME = "Suspicious Multi-Stage Activity"

SEQUENCE_WINDOW_MINUTES = 60
FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW_MINUTES = 5

SEVERITY = "critical"


def parse_event_time(value):
    """Convert an event timestamp into UTC."""

    if not value:
        return None

    try:
        timestamp = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except (ValueError, AttributeError):
        return None

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc)


def is_encoded_powershell(event):
    """Check whether an event contains encoded PowerShell execution."""

    if event.get("event_type") != "process_execution":
        return False

    if (event.get("process") or "").lower() != "powershell.exe":
        return False

    command_line = (event.get("command_line") or "").lower()

    return any(
        indicator in command_line
        for indicator in ("-encodedcommand", "-enc")
    )


def find_behavioral_sequences(events):
    """
    Identify a chronological sequence of suspicious activity:

    1. Five failed logins.
    2. Successful login.
    3. Encoded PowerShell execution.
    4. Outbound network connection.

    Events must share the relevant identity, source IP or hostname.
    """

    valid_events = []

    for event in events:
        timestamp = parse_event_time(event.get("timestamp"))

        if timestamp is None:
            continue

        if event.get("id") is None:
            continue

        valid_events.append((timestamp, event))

    valid_events.sort(key=lambda item: item[0])

    alerts = []
    processed_sequences = set()

    for first_time, first_event in valid_events:

        if (
            first_event.get("event_type") != "authentication"
            or first_event.get("status") != "failed"
        ):
            continue

        username = first_event.get("username")
        source_ip = first_event.get("source_ip")
        hostname = first_event.get("host")

        if not username or not source_ip or not hostname:
            continue

        sequence_end = first_time + timedelta(
            minutes=SEQUENCE_WINDOW_MINUTES
        )

        failed_events = [
            event
            for timestamp, event in valid_events
            if (
                first_time <= timestamp
                <= first_time + timedelta(
                    minutes=FAILED_LOGIN_WINDOW_MINUTES
                )
                and event.get("event_type") == "authentication"
                and event.get("status") == "failed"
                and event.get("username") == username
                and event.get("source_ip") == source_ip
                and event.get("host") == hostname
            )
        ]

        if len(failed_events) < FAILED_LOGIN_THRESHOLD:
            continue

        failed_ids = {
            event["id"] for event in failed_events
        }

        for success_time, success_event in valid_events:

            latest_failed_time = max(
                parse_event_time(event["timestamp"])
                for event in failed_events
            )

            if not (
                latest_failed_time < success_time <= sequence_end
            ):
                continue

            if not (
                success_event.get("event_type") == "authentication"
                and success_event.get("status") == "success"
                and success_event.get("username") == username
                and success_event.get("source_ip") == source_ip
                and success_event.get("host") == hostname
            ):
                continue

            for powershell_time, powershell_event in valid_events:

                if not (
                    success_time < powershell_time <= sequence_end
                ):
                    continue

                if (
                    powershell_event.get("username") != username
                    or powershell_event.get("host") != hostname
                    or not is_encoded_powershell(powershell_event)
                ):
                    continue

                for network_time, network_event in valid_events:

                    if not (
                        powershell_time < network_time <= sequence_end
                    ):
                        continue

                    if not (
                        network_event.get("event_type")
                        == "network_connection"
                        and network_event.get("host") == hostname
                    ):
                        continue

                    evidence = (
                        sorted(
                            failed_events,
                            key=lambda event: parse_event_time(
                                event["timestamp"]
                            )
                        )
                        + [
                            success_event,
                            powershell_event,
                            network_event,
                        ]
                    )

                    evidence_ids = [
                        event["id"] for event in evidence
                    ]

                    sequence_key = tuple(evidence_ids)

                    if sequence_key in processed_sequences:
                        continue

                    processed_sequences.add(sequence_key)

                    alerts.append({
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "description": (
                            "A sequence of repeated failed logins, "
                            "successful authentication, encoded "
                            "PowerShell execution and outbound "
                            "network activity was detected. "
                            "This sequence requires investigation "
                            "and does not independently confirm compromise."
                        ),
                        "username": username,
                        "source_ip": source_ip,
                        "destination_ip": network_event.get(
                            "destination_ip"
                        ),
                        "process": powershell_event.get("process"),
                        "command_line": powershell_event.get(
                            "command_line"
                        ),
                        "event_count": len(evidence_ids),
                        "evidence": evidence_ids,
                        "mitre_attack": {
                            "tactic": "Credential Access, Execution",
                            "technique_id": "T1110, T1059.001",
                            "technique": "Brute Force, PowerShell",
                        },
                        "behavioral_context": {
                            "sequence": [
                                "repeated_failed_logins",
                                "successful_login",
                                "encoded_powershell",
                                "outbound_network_connection",
                            ],
                            "time_window_minutes": (
                                SEQUENCE_WINDOW_MINUTES
                            ),
                            "correlation_reason": (
                                "Shared username, source IP and "
                                "hostname across a chronological "
                                "sequence of events."
                            ),
                        },
                    })

    return alerts
