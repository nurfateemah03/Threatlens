
SEVERITY_SCORES = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10
}


def calculate_severity_score(alerts):
    """
    Calculate a base incident score using alert severity.
    Uses the highest-severity alert as the base score.
    """

    if not alerts:
        return 0

    scores = [
        SEVERITY_SCORES.get(
            alert.get("severity", "low").lower(),
            10
        )
        for alert in alerts
    ]

    return max(scores)
