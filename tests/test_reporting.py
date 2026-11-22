
from unittest.mock import patch

from reporting.report_generator import (
    generate_json_report,
    generate_pdf_report,
)


SAMPLE_REPORT = {
    "report_metadata": {
        "platform": "ThreatLens",
        "report_type": "Incident Report",
        "generated_at": "2026-11-22T16:00:00+00:00",
    },
    "incident": {
        "id": 1,
        "title": "Encoded PowerShell Execution",
        "description": "Synthetic test incident",
        "severity": "medium",
        "priority": "medium",
        "priority_score": 33,
        "status": "open",
        "created_at": "2026-11-22T15:00:00",
        "updated_at": "2026-11-22T15:00:00",
        "resolved_at": None,
        "alert_count": 1,
    },
    "risk_assessment": {
        "score": 33,
        "priority": "medium",
        "breakdown": {
            "severity": 20,
            "alert_volume": 0,
            "threat_intelligence": 0,
            "mitre": 3,
        },
    },
    "alerts": [],
    "analyst_notes": [],
    "incident_timeline": [],
}


def test_generate_json_report():
    with patch(
        "reporting.report_generator.build_incident_report",
        return_value=SAMPLE_REPORT,
    ):
        result = generate_json_report(1)

    assert isinstance(result, bytes)
    assert b"Encoded PowerShell Execution" in result
    assert b"risk_assessment" in result


def test_generate_pdf_report():
    with patch(
        "reporting.report_generator.build_incident_report",
        return_value=SAMPLE_REPORT,
    ):
        result = generate_pdf_report(1)

    assert isinstance(result, bytes)
    assert result.startswith(b"%PDF-")


def test_json_report_contains_incident_status():
    with patch(
        "reporting.report_generator.build_incident_report",
        return_value=SAMPLE_REPORT,
    ):
        result = generate_json_report(1)

    assert b'"status": "open"' in result
