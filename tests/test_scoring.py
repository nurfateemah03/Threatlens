
from intelligence.scoring import calculate_severity_score


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
