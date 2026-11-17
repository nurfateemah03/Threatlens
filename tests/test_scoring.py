
from intelligence.scoring import (
    calculate_severity_score,
    calculate_alert_volume_score,
    calculate_threat_intelligence_score,
    calculate_mitre_score,
    calculate_incident_score,
    classify_incident_priority,
)
def test_critical_alert_scores_40():
    alerts = [{"severity": "critical"}]
    assert calculate_severity_score(alerts) == 40


def test_high_alert_scores_30():
    alerts = [{"severity": "high"}]
    assert calculate_severity_score(alerts) == 30


def test_medium_alert_scores_20():
    alerts = [{"severity": "medium"}]
    assert calculate_severity_score(alerts) == 20


def test_low_alert_scores_10():
    alerts = [{"severity": "low"}]
    assert calculate_severity_score(alerts) == 10


def test_highest_severity_is_used():
    alerts = [
        {"severity": "low"},
        {"severity": "medium"},
        {"severity": "critical"}
    ]
    assert calculate_severity_score(alerts) == 40


def test_empty_alerts_return_zero():
    assert calculate_severity_score([]) == 0
from intelligence.scoring import calculate_alert_volume_score


def test_single_alert_has_no_volume_bonus():
    alerts = [{"severity": "high"}]
    assert calculate_alert_volume_score(alerts) == 0


def test_two_alerts_receive_small_bonus():
    alerts = [{}, {}]
    assert calculate_alert_volume_score(alerts) == 5


def test_four_alerts_receive_medium_bonus():
    alerts = [{}, {}, {}, {}]
    assert calculate_alert_volume_score(alerts) == 10


def test_many_alerts_receive_capped_bonus():
    alerts = [{} for _ in range(10)]
    assert calculate_alert_volume_score(alerts) == 15


def test_empty_alerts_have_no_volume_bonus():
    assert calculate_alert_volume_score([]) == 0


def test_virustotal_malicious_detection_adds_10():
    alerts = [{
        "external_intelligence": {
            "providers": {
                "virustotal": {
                    "status": "success",
                    "data": {
                        "analysis_stats": {"malicious": 3}
                    }
                }
            }
        }
    }]

    assert calculate_threat_intelligence_score(alerts) == 10


def test_virustotal_suspicious_detection_adds_5():
    alerts = [{
        "external_intelligence": {
            "providers": {
                "virustotal": {
                    "status": "success",
                    "data": {
                        "analysis_stats": {"suspicious": 2}
                    }
                }
            }
        }
    }]

    assert calculate_threat_intelligence_score(alerts) == 5


def test_malicious_takes_precedence_over_suspicious():
    alerts = [{
        "external_intelligence": {
            "providers": {
                "virustotal": {
                    "status": "success",
                    "data": {
                        "analysis_stats": {
                            "malicious": 2,
                            "suspicious": 3
                        }
                    }
                }
            }
        }
    }]

    assert calculate_threat_intelligence_score(alerts) == 10


def test_otx_pulse_adds_5():
    alerts = [{
        "external_intelligence": {
            "providers": {
                "otx": {
                    "status": "success",
                    "data": {"pulse_count": 2}
                }
            }
        }
    }]

    assert calculate_threat_intelligence_score(alerts) == 5


def test_both_providers_add_their_scores():
    alerts = [{
        "external_intelligence": {
            "providers": {
                "virustotal": {
                    "status": "success",
                    "data": {
                        "analysis_stats": {"malicious": 1}
                    }
                },
                "otx": {
                    "status": "success",
                    "data": {"pulse_count": 1}
                }
            }
        }
    }]

    assert calculate_threat_intelligence_score(alerts) == 15


def test_failed_provider_does_not_add_score():
    alerts = [{
        "external_intelligence": {
            "providers": {
                "virustotal": {"status": "error"},
                "otx": {"status": "error"}
            }
        }
    }]

    assert calculate_threat_intelligence_score(alerts) == 0


def test_intelligence_score_is_capped_at_25():
    alerts = [{
        "external_intelligence": {
            "providers": {
                "virustotal": {
                    "status": "success",
                    "data": {
                        "analysis_stats": {"malicious": 1}
                    }
                },
                "otx": {
                    "status": "success",
                    "data": {"pulse_count": 1}
                }
            }
        }
    } for _ in range(3)]

    assert calculate_threat_intelligence_score(alerts) == 25


def test_missing_intelligence_returns_zero():
    assert calculate_threat_intelligence_score([{}]) == 0    

def test_mitre_technique_adds_5():
    alerts = [{"mitre_technique_id": "T1110"}]

    assert calculate_mitre_score(alerts) == 5


def test_mitre_tactic_adds_3():
    alerts = [{"mitre_tactic": "Credential Access"}]

    assert calculate_mitre_score(alerts) == 3


def test_technique_and_tactic_add_8():
    alerts = [{
        "mitre_technique_id": "T1110",
        "mitre_tactic": "Credential Access"
    }]

    assert calculate_mitre_score(alerts) == 8


def test_multiple_distinct_techniques_add_bonus():
    alerts = [
        {"mitre_technique_id": "T1110"},
        {"mitre_technique_id": "T1059"}
    ]

    assert calculate_mitre_score(alerts) == 7


def test_duplicate_techniques_are_not_counted_twice():
    alerts = [
        {"mitre_technique_id": "T1110"},
        {"mitre_technique_id": "T1110"},
        {"mitre_technique_id": "T1110"}
    ]

    assert calculate_mitre_score(alerts) == 5


def test_mitre_score_is_capped_at_10():
    alerts = [
        {
            "mitre_technique_id": f"T1059.{i:03d}",
            "mitre_tactic": f"Tactic {i}"
        }
        for i in range(10)
    ]

    assert calculate_mitre_score(alerts) == 10


def test_missing_mitre_context_returns_zero():
    assert calculate_mitre_score([{}]) == 0


def test_empty_alerts_return_zero_mitre_score():
    assert calculate_mitre_score([]) == 0

def test_empty_incident_has_zero_score():
    result = calculate_incident_score([])

    assert result["score"] == 0
    assert result["priority"] == "low"


def test_severity_score_is_combined_correctly():
    alerts = [{"severity": "high"}]

    result = calculate_incident_score(alerts)

    assert result["score"] == 30
    assert result["priority"] == "medium"


def test_all_scoring_dimensions_are_combined():
    alerts = [{
        "severity": "high",
        "mitre_technique_id": "T1110",
        "mitre_tactic": "Credential Access",
        "external_intelligence": {
            "providers": {
                "virustotal": {
                    "status": "success",
                    "data": {
                        "analysis_stats": {"malicious": 2}
                    }
                },
                "otx": {
                    "status": "success",
                    "data": {"pulse_count": 1}
                }
            }
        }
    } for _ in range(2)]

    result = calculate_incident_score(alerts)

    assert result["breakdown"] == {
        "severity": 30,
        "alert_volume": 5,
        "threat_intelligence": 25,
        "mitre": 8,
    }

    assert result["score"] == 68
    assert result["priority"] == "high"


def test_critical_priority_classification():
    assert classify_incident_priority(70) == "critical"


def test_high_priority_classification():
    assert classify_incident_priority(45) == "high"


def test_medium_priority_classification():
    assert classify_incident_priority(25) == "medium"


def test_low_priority_classification():
    assert classify_incident_priority(24) == "low"


def test_maximum_score_is_90():
    alerts = [{
        "severity": "critical",
        "mitre_technique_id": f"T1059.{i:03d}",
        "mitre_tactic": "Credential Access",
        "external_intelligence": {
            "providers": {
                "virustotal": {
                    "status": "success",
                    "data": {
                        "analysis_stats": {"malicious": 5}
                    }
                },
                "otx": {
                    "status": "success",
                    "data": {"pulse_count": 5}
                }
            }
        }
    } for i in range(10)]

    result = calculate_incident_score(alerts)

    assert result["score"] == 90
    assert result["priority"] == "critical"
def test_sqlite_json_string_enrichment_is_scored():
    import json

    alerts = [{
        "enrichment_json": json.dumps({
            "local": None,
            "external": {
                "providers": {
                    "virustotal": {
                        "status": "success",
                        "data": {
                            "analysis_stats": {
                                "malicious": 3
                            }
                        }
                    }
                }
            }
        })
    }]

    assert calculate_threat_intelligence_score(alerts) == 10