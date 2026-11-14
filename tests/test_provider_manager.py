from unittest.mock import patch
from enrichment.provider_manager import enrich_indicator


@patch("enrichment.provider_manager.otx_lookup")
@patch("enrichment.provider_manager.vt_lookup")
def test_both_providers_succeed(mock_vt, mock_otx, tmp_path):
    mock_vt.return_value = {"data": {"attributes": {}}}
    mock_otx.return_value = {"pulse_info": {"count": 0, "pulses": []}}
    db_path = tmp_path / "test.db"
    with patch(
        "enrichment.provider_manager.vt_summarize",
        return_value={"malicious": 2}
    ), patch(
        "enrichment.provider_manager.otx_summarize",
        return_value={"pulse_count": 0}
    ):
        result = enrich_indicator(
        "example.com",
        "domain",
        db_path=db_path
        )
    assert result["providers"]["virustotal"]["status"] == "success"
    assert result["providers"]["otx"]["status"] == "success"


@patch("enrichment.provider_manager.otx_lookup")
@patch("enrichment.provider_manager.vt_lookup")
def test_one_provider_failure_does_not_stop_other(mock_vt, mock_otx, tmp_path):
    from enrichment.provider_manager import VirusTotalError
    db_path = tmp_path / "test.db"


    mock_vt.side_effect = VirusTotalError("API unavailable")
    mock_otx.return_value = {"pulse_info": {"count": 0, "pulses": []}}

    with patch(
        "enrichment.provider_manager.otx_summarize",
        return_value={"pulse_count": 0}
    ):
         result = enrich_indicator(
        "example.com",
        "domain",
        db_path=db_path
         )

    assert result["providers"]["virustotal"]["status"] == "error"
    assert result["providers"]["otx"]["status"] == "success"


@patch("enrichment.provider_manager.otx_lookup")
@patch("enrichment.provider_manager.vt_lookup")
def test_both_provider_failures_are_recorded(mock_vt, mock_otx, tmp_path):
    from enrichment.provider_manager import VirusTotalError, OTXError
    db_path = tmp_path / "test.db"

    mock_vt.side_effect = VirusTotalError("VT unavailable")
    mock_otx.side_effect = OTXError("OTX unavailable")

    result = enrich_indicator(
        "example.com",
        "domain",
        db_path=db_path
    )
    assert result["providers"]["virustotal"]["status"] == "error"
    assert result["providers"]["otx"]["status"] == "error"


@patch("enrichment.provider_manager.otx_lookup")
@patch("enrichment.provider_manager.vt_lookup")
def test_indicator_information_is_preserved(mock_vt, mock_otx, tmp_path):
    db_path = tmp_path / "test.db"

    mock_vt.return_value = {"data": {"attributes": {}}}
    mock_otx.return_value = {"pulse_info": {"count": 0, "pulses": []}}

    with patch(
        "enrichment.provider_manager.vt_summarize",
        return_value={}
    ), patch(
        "enrichment.provider_manager.otx_summarize",
        return_value={}
    ):
           result = enrich_indicator(
        "example.com",
        "domain",
        db_path=db_path
    )

    assert result["indicator"] == "example.com"
    assert result["indicator_type"] == "domain"
