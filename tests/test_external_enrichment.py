
from unittest.mock import patch

from database.models import initialize_db
from enrichment.provider_manager import enrich_indicator


@patch("enrichment.provider_manager.otx_lookup")
@patch("enrichment.provider_manager.vt_lookup")
def test_external_enrichment_and_cache(
    mock_vt,
    mock_otx,
    tmp_path
):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    mock_vt.return_value = {
        "data": {
            "id": "198.51.100.25",
            "type": "ip_address"
        }
    }

    mock_otx.return_value = {
        "pulse_info": {
            "count": 1,
            "pulses": [{"name": "Test campaign"}]
        }
    }

    with patch(
        "enrichment.provider_manager.vt_summarize",
        return_value={"malicious": 2}
    ), patch(
        "enrichment.provider_manager.otx_summarize",
        return_value={"pulse_count": 1}
    ):

        first_result = enrich_indicator(
            "198.51.100.25",
            "ip",
            db_path
        )

        assert first_result["providers"]["virustotal"]["cached"] is False
        assert first_result["providers"]["otx"]["cached"] is False

        second_result = enrich_indicator(
            "198.51.100.25",
            "ip",
            db_path
        )

        assert second_result["providers"]["virustotal"]["cached"] is True
        assert second_result["providers"]["otx"]["cached"] is True

    assert mock_vt.call_count == 1
    assert mock_otx.call_count == 1


@patch("enrichment.provider_manager.otx_lookup")
@patch("enrichment.provider_manager.vt_lookup")
def test_failed_provider_does_not_get_cached(
    mock_vt,
    mock_otx,
    tmp_path
):
    from enrichment.providers.virustotal import VirusTotalError

    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    mock_vt.side_effect = VirusTotalError("API unavailable")

    mock_otx.return_value = {
        "pulse_info": {
            "count": 0,
            "pulses": []
        }
    }

    with patch(
        "enrichment.provider_manager.otx_summarize",
        return_value={"pulse_count": 0}
    ):
        result = enrich_indicator(
            "example.com",
            "domain",
            db_path
        )

    assert result["providers"]["virustotal"]["status"] == "error"
    assert result["providers"]["otx"]["status"] == "success"


def test_alert_indicator_selection():
    from detection.runner import get_alert_indicator

    alert = {
        "destination_ip": "198.51.100.25",
        "source_ip": "203.0.113.50"
    }

    indicator, indicator_type = get_alert_indicator(alert)

    assert indicator == "198.51.100.25"
    assert indicator_type == "ip"


def test_alert_without_indicator():
    from detection.runner import get_alert_indicator

    indicator, indicator_type = get_alert_indicator({})

    assert indicator is None
    assert indicator_type is None



def test_alert_persistence_includes_external_intelligence(tmp_path):
    from database.models import (
        initialize_db,
        save_alerts,
        get_alerts
    )

    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    alert = {
        "rule_id": "TL-003",
        "rule_name": "Connection to Known Malicious IP",
        "severity": "high",
        "description": "Synthetic test alert",
        "evidence": [1],
        "threat_intelligence": {
            "classification": "synthetic_test_indicator"
        },
        "external_intelligence": {
            "indicator": "198.51.100.25",
            "providers": {
                "virustotal": {
                    "status": "success",
                    "data": {"malicious": 2}
                }
            }
        }
    }

    save_alerts([alert], db_path)

    stored_alerts = get_alerts(db_path)

    assert len(stored_alerts) == 1

    enrichment = stored_alerts[0]["enrichment_json"]

    assert enrichment["local"]["classification"] == (
        "synthetic_test_indicator"
    )

    assert enrichment["external"]["indicator"] == "198.51.100.25"
