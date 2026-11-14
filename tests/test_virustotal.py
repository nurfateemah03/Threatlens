
import pytest
from unittest.mock import Mock, patch

from enrichment.providers.virustotal import (
    lookup_indicator,
    summarize_report,
    VirusTotalError
)


def test_rejects_invalid_indicator_type():
    with pytest.raises(ValueError):
        lookup_indicator("example.com", "invalid", api_key="test")


@patch("enrichment.providers.virustotal.requests.get")
def test_successful_ip_lookup(mock_get):
    mock_response = Mock()
    mock_response.json.return_value = {
        "data": {
            "id": "198.51.100.25",
            "type": "ip_address"
        }
    }

    mock_get.return_value = mock_response

    result = lookup_indicator(
        "198.51.100.25",
        "ip",
        api_key="test-key"
    )

    assert result["data"]["id"] == "198.51.100.25"
    mock_get.assert_called_once()


def test_missing_api_key():
    with patch(
        "enrichment.providers.virustotal.os.getenv",
        return_value=None
    ):
        with pytest.raises(VirusTotalError):
            lookup_indicator("198.51.100.25", "ip")

def test_summarize_virustotal_report():
    report = {
        "data": {
            "id": "example.com",
            "type": "domain",
            "attributes": {
                "reputation": 85,
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "harmless": 50,
                    "undetected": 20,
                    "timeout": 2
                },
                "last_analysis_date": 1794660000
            }
        }
    }

    result = summarize_report(report)

    assert result["indicator"] == "example.com"
    assert result["indicator_type"] == "domain"
    assert result["reputation"] == 85
    assert result["analysis_stats"]["malicious"] == 2
    assert result["total_engines"] == 75
    assert result["last_analysis_date"] is not None


def test_summarize_report_with_missing_fields():
    report = {
        "data": {
            "id": "example.com",
            "type": "domain",
            "attributes": {}
        }
    }

    result = summarize_report(report)

    assert result["reputation"] == 0
    assert result["analysis_stats"]["malicious"] == 0
    assert result["total_engines"] == 0
    assert result["last_analysis_date"] is None


def test_summarize_report_rejects_invalid_structure():
    import pytest

    with pytest.raises(ValueError):
        summarize_report({})