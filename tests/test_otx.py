
import pytest
from unittest.mock import Mock, patch

from enrichment.providers.otx import (
    lookup_indicator,
    summarize_report,
    OTXError
)


def test_rejects_invalid_indicator_type():
    with pytest.raises(ValueError):
        lookup_indicator(
            "example.com",
            "invalid",
            api_key="test"
        )


@patch("enrichment.providers.otx.requests.get")
def test_successful_ip_lookup(mock_get):
    mock_response = Mock()
    mock_response.json.return_value = {
        "pulse_info": {
            "count": 2,
            "pulses": []
        }
    }

    mock_get.return_value = mock_response

    result = lookup_indicator(
        "198.51.100.25",
        "ip",
        api_key="test-key"
    )

    assert result["pulse_info"]["count"] == 2
    mock_get.assert_called_once()


def test_missing_api_key():
    with patch(
        "enrichment.providers.otx.os.getenv",
        return_value=None
    ):
        with pytest.raises(OTXError):
            lookup_indicator("example.com", "domain")


def test_summarize_report():
    report = {
        "pulse_info": {
            "count": 2,
            "pulses": [
                {"name": "Example phishing campaign"},
                {"name": "Credential theft campaign"}
            ]
        }
    }

    result = summarize_report(report)

    assert result["pulse_count"] == 2
    assert len(result["pulse_names"]) == 2


def test_summarize_empty_report():
    report = {
        "pulse_info": {
            "count": 0,
            "pulses": []
        }
    }

    result = summarize_report(report)

    assert result["pulse_count"] == 0
    assert result["pulse_names"] == []


def test_summarize_invalid_report():
    with pytest.raises(ValueError):
        summarize_report({})
