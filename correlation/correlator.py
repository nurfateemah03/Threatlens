
from datetime import datetime, timedelta, timezone

from database.models import (
    DEFAULT_DB_PATH,
    create_incident,
    get_incidents,
    get_incident_alerts,
    link_alert_to_incident,
    merge_incidents,
)


CORRELATION_FIELDS = (
    "username",
    "source_ip",
    "destination_ip",
)

ACTIVE_STATUSES = {"open", "investigating"}


def parse_alert_time(value):
    """Convert an alert timestamp into a timezone-aware datetime."""

    if not value:
        return None

    if isinstance(value, datetime):
        timestamp = value
    else:
        try:
            timestamp = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except (ValueError, AttributeError):
            return None

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc)


def find_correlation_matches(
    new_alert,
    existing_alert,
    window_minutes=30
):
    """Check whether two alerts meet the correlation criteria."""

    new_time = parse_alert_time(new_alert.get("created_at"))
    existing_time = parse_alert_time(existing_alert.get("created_at"))

    if new_time is None or existing_time is None:
        return []

    if abs(new_time - existing_time) > timedelta(
        minutes=window_minutes
    ):
        return []

    matching_fields = []

    for field in CORRELATION_FIELDS:
        new_value = new_alert.get(field)
        existing_value = existing_alert.get(field)

        if (
            new_value
            and existing_value
            and new_value == existing_value
        ):
            matching_fields.append(field)

    if len(matching_fields) < 2:
        return []

    return matching_fields


def get_existing_incident_for_alert(alert_id, db_path):
    """Prevent an alert from being assigned to multiple incidents."""

    for incident in get_incidents(db_path):
        incident_alerts = get_incident_alerts(
            incident["id"],
            db_path
        )

        if any(alert["id"] == alert_id for alert in incident_alerts):
            return incident

    return None


def correlate_alert(
    alert,
    db_path=DEFAULT_DB_PATH,
    window_minutes=30
):
    """
    Create an incident for an alert, then merge it into an
    existing related incident when a correlation match exists.
    """

    if not alert.get("id") or not alert.get("fingerprint"):
        raise ValueError(
            "Alert must have a persisted ID and fingerprint"
        )

    # Make the operation idempotent.
    existing_assignment = get_existing_incident_for_alert(
        alert["id"],
        db_path
    )

    if existing_assignment:
        return existing_assignment

    # Step 1: Create a provisional incident.
    provisional = create_incident(
        fingerprint=f"alert:{alert['fingerprint']}",
        title=alert.get("rule_name") or "Security alert",
        severity=alert.get("severity", "low"),
        description=alert.get("description"),
        db_path=db_path
    )

    # Step 2: Link the new alert to its provisional incident.
    link_alert_to_incident(
        provisional["id"],
        alert["id"],
        db_path
    )

    # Step 3: Look for related alerts in active incidents.
    for incident in get_incidents(db_path):

        if incident["id"] == provisional["id"]:
            continue

        if incident["status"] not in ACTIVE_STATUSES:
            continue

        existing_alerts = get_incident_alerts(
            incident["id"],
            db_path
        )

        for existing_alert in existing_alerts:
            matches = find_correlation_matches(
                alert,
                existing_alert,
                window_minutes
            )

            if matches:
                # Step 4: Merge provisional into the existing incident.
                return merge_incidents(
                    provisional["id"],
                    incident["id"],
                    db_path
                )

    # No related incident found.
    return provisional
