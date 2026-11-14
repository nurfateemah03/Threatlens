
from detection.engine import (
    load_rule,
    detect_brute_force,
    detect_encoded_powershell,
    detect_malicious_ip,
    run_detection_engine
)

def create_failed_login(minute, username="admin", source_ip="192.0.2.15"):
    return {
        "id": minute + 1,
        "timestamp": f"2026-11-14T10:{minute:02d}:00Z",
        "event_type": "authentication",
        "status": "failed",
        "username": username,
        "source_ip": source_ip,
    }


def test_detects_five_failed_logins():
    events = [create_failed_login(i) for i in range(5)]

    rule = load_rule("brute_force.yaml")
    alerts = detect_brute_force(events, rule)

    assert len(alerts) == 1
    assert alerts[0]["event_count"] == 5
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["mitre_attack"]["technique_id"] == "T1110"


def test_does_not_detect_four_failed_logins():
    events = [create_failed_login(i) for i in range(4)]

    rule = load_rule("brute_force.yaml")
    alerts = detect_brute_force(events, rule)

    assert len(alerts) == 0


def test_does_not_detect_attempts_outside_time_window():
    events = [
        create_failed_login(0),
        create_failed_login(1),
        create_failed_login(2),
        create_failed_login(3),
        create_failed_login(10),
    ]

    rule = load_rule("brute_force.yaml")
    alerts = detect_brute_force(events, rule)

    assert len(alerts) == 0


def test_detects_encoded_powershell():
    events = [{
        "id": 10,
        "event_type": "process_execution",
        "process": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand SQBFAFgA..."
    }]

    rule = load_rule("powershell.yaml")
    alerts = detect_encoded_powershell(events, rule)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "TL-002"
    assert alerts[0]["severity"] == "medium"
    assert alerts[0]["mitre_attack"]["technique_id"] == "T1059.001"


def test_does_not_detect_normal_powershell():
    events = [{
        "id": 11,
        "event_type": "process_execution",
        "process": "powershell.exe",
        "command_line": "powershell.exe Get-Process"
    }]

    rule = load_rule("powershell.yaml")
    alerts = detect_encoded_powershell(events, rule)

    assert len(alerts) == 0


def test_does_not_detect_encoded_command_in_other_process():
    events = [{
        "id": 12,
        "event_type": "process_execution",
        "process": "cmd.exe",
        "command_line": "cmd.exe -EncodedCommand example"
    }]

    rule = load_rule("powershell.yaml")
    alerts = detect_encoded_powershell(events, rule)

    assert len(alerts) == 0


def test_detects_malicious_ip():
    events = [{
        "id": 20,
        "event_type": "network_connection",
        "destination_ip": "198.51.100.25"
    }]

    rule = load_rule("malicious_ip.yaml")
    alerts = detect_malicious_ip(events, rule)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "TL-003"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["destination_ip"] == "198.51.100.25"


def test_does_not_detect_unknown_ip():
    events = [{
        "id": 21,
        "event_type": "network_connection",
        "destination_ip": "192.0.2.100"
    }]

    rule = load_rule("malicious_ip.yaml")
    alerts = detect_malicious_ip(events, rule)

    assert len(alerts) == 0

def test_unified_detection_engine():
    events = [
        {
            "id": i + 1,
            "timestamp": f"2026-11-14T10:0{i}:00Z",
            "event_type": "authentication",
            "status": "failed",
            "username": "admin",
            "source_ip": "192.0.2.15"
        }
        for i in range(5)
    ]

    events.extend([
        {
            "id": 10,
            "event_type": "process_execution",
            "process": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand example"
        },
        {
            "id": 11,
            "event_type": "network_connection",
            "destination_ip": "198.51.100.25"
        }
    ])

    alerts = run_detection_engine(events)

    detected_rules = {alert["rule_id"] for alert in alerts}

    assert detected_rules == {"TL-001", "TL-002", "TL-003"}
    assert len(alerts) == 3
