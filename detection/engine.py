
import yaml
from pathlib import Path


RULES_DIRECTORY = Path("detection/rules")


def load_rule(rule_name):
    """Load an individual YAML detection rule."""

    rule_path = RULES_DIRECTORY / rule_name

    with open(rule_path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def load_all_rules():
    """Load every YAML detection rule."""

    rules = {}

    for rule_path in RULES_DIRECTORY.glob("*.yaml"):

        with open(rule_path, "r", encoding="utf-8") as file:
            rule = yaml.safe_load(file)

        rules[rule["id"]] = rule

    return rules

from datetime import datetime, timedelta, timezone


def parse_event_time(value):
    """Convert an event timestamp to a datetime."""

    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    ).astimezone(timezone.utc)


def detect_brute_force(events, rule):
    """
    Detect repeated failed logins from the same
    username and source IP within a time window.
    """

    config = rule["detection"]

    threshold = config["threshold"]
    window = timedelta(minutes=config["window_minutes"])

    groups = {}

    for event in events:

        if event["event_type"] != config["event_type"]:
            continue

        if event["status"] != config["status"]:
            continue

        key = (
            event["username"],
            event["source_ip"]
        )

        groups.setdefault(key, []).append(event)

    alerts = []

    for (username, source_ip), attempts in groups.items():

        attempts.sort(
            key=lambda event: parse_event_time(event["timestamp"])
        )

        for index, current_event in enumerate(attempts):

            current_time = parse_event_time(
                current_event["timestamp"]
            )

            matching_events = [
                event for event in attempts
                if timedelta(0) <= (
                    current_time - parse_event_time(event["timestamp"])
                ) <= window
            ]

            if len(matching_events) >= threshold:

                alerts.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "username": username,
                    "source_ip": source_ip,
                    "event_count": len(matching_events),
                    "mitre_attack": rule["mitre_attack"],
                    "evidence": [
                        event["id"]
                        for event in matching_events
                    ]
                })

                break

    return alerts


def detect_encoded_powershell(events, rule):
    config = rule["detection"]
    alerts = []

    for event in events:
        if event["event_type"] != config["event_type"]:
            continue

        process = (event.get("process") or "").lower()

        if process != config["process"].lower():
            continue

        command_line = event.get("command_line") or ""
        command_lower = command_line.lower()

        indicators = [
            indicator.lower()
            for indicator in config["indicators"]
        ]

        if any(indicator in command_lower for indicator in indicators):
            alerts.append({
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "description": rule["description"],
                "process": event["process"],
                "command_line": command_line,
                "mitre_attack": rule["mitre_attack"],
                "evidence": [event["id"]]
            })

    return alerts


def detect_malicious_ip(events, rule):
    config = rule["detection"]

    ioc_path = Path("intelligence/ioc_list.txt")

    with open(ioc_path, "r", encoding="utf-8") as file:
        malicious_ips = {
            line.strip()
            for line in file
            if line.strip() and not line.strip().startswith("#")
        }

    alerts = []

    for event in events:
        if event["event_type"] != config["event_type"]:
            continue

        destination_ip = event.get(config["indicator_field"])

        if destination_ip not in malicious_ips:
            continue

        alerts.append({
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "severity": rule["severity"],
            "description": rule["description"],
            "destination_ip": destination_ip,
            "mitre_attack": rule["mitre_attack"],
            "evidence": [event["id"]]
        })

    return alerts


def run_detection_engine(events):
    rules = load_all_rules()

    detectors = {
        "TL-001": detect_brute_force,
        "TL-002": detect_encoded_powershell,
        "TL-003": detect_malicious_ip,
    }

    all_alerts = []

    for rule_id, detector in detectors.items():
        rule = rules.get(rule_id)

        if rule is None:
            continue

        alerts = detector(events, rule)
        all_alerts.extend(alerts)

    return all_alerts
