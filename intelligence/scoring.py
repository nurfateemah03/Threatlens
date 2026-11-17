import json
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
def calculate_alert_volume_score(alerts):
    """
    Add a capped score based on the number of alerts
    associated with an incident.
    """
    alert_count = len(alerts)

    if alert_count <= 1:
        return 0
    elif alert_count <= 3:
        return 5
    elif alert_count <= 5:
        return 10
    else:
        return 15

def calculate_threat_intelligence_score(alerts):
    """
    Score an incident using supporting external threat intelligence.

    VirusTotal malicious detections: +10
    VirusTotal suspicious detections: +5
    AlienVault OTX matching pulses: +5

    Maximum incident intelligence bonus: 25.
    Supports both in-memory and SQLite-loaded alert data.
    """
    total_score = 0

    for alert in alerts:
        enrichment = alert.get("external_intelligence")

        if enrichment is None:
            stored_enrichment = alert.get("enrichment_json") or {}

            # SQLite may return the JSON as a string.
            if isinstance(stored_enrichment, str):
                try:
                    stored_enrichment = json.loads(stored_enrichment)
                except json.JSONDecodeError:
                    stored_enrichment = {}

            if isinstance(stored_enrichment, dict):
                enrichment = stored_enrichment.get("external", {})
            else:
                enrichment = {}

        if not isinstance(enrichment, dict):
            continue

        providers = enrichment.get("providers", {})

        if not isinstance(providers, dict):
            continue

        alert_score = 0

        # VirusTotal
        vt_result = providers.get("virustotal", {})

        if vt_result.get("status") == "success":
            vt_data = vt_result.get("data", {})
            stats = vt_data.get("analysis_stats", {})

            if stats.get("malicious", 0) > 0:
                alert_score += 10
            elif stats.get("suspicious", 0) > 0:
                alert_score += 5

        # AlienVault OTX
        otx_result = providers.get("otx", {})

        if otx_result.get("status") == "success":
            otx_data = otx_result.get("data", {})

            if otx_data.get("pulse_count", 0) > 0:
                alert_score += 5

        total_score += alert_score

    return min(total_score, 25)
def calculate_mitre_score(alerts):
    """
    Score an incident based on its mapped MITRE ATT&CK context.

    At least one mapped technique: +5
    At least one mapped tactic: +3
    Multiple distinct techniques: +2

    Maximum MITRE bonus: 10
    """
    techniques = set()
    tactics = set()

    for alert in alerts:
        technique_id = alert.get("mitre_technique_id")
        tactic = alert.get("mitre_tactic")

        if technique_id:
            techniques.add(technique_id)

        if tactic:
            tactics.add(tactic)

    score = 0

    if techniques:
        score += 5

    if tactics:
        score += 3

    if len(techniques) >= 2:
        score += 2

    return min(score, 10)    
def classify_incident_priority(score):
    """
    Convert a numeric incident score into a priority classification.
    """
    if score >= 70:
        return "critical"
    elif score >= 45:
        return "high"
    elif score >= 25:
        return "medium"
    else:
        return "low"


def calculate_incident_score(alerts):
    """
    Calculate an explainable incident score from four dimensions.

    Maximum possible score: 90.
    """
    if not alerts:
        return {
            "score": 0,
            "priority": "low",
            "breakdown": {
                "severity": 0,
                "alert_volume": 0,
                "threat_intelligence": 0,
                "mitre": 0,
            }
        }

    breakdown = {
        "severity": calculate_severity_score(alerts),
        "alert_volume": calculate_alert_volume_score(alerts),
        "threat_intelligence": calculate_threat_intelligence_score(alerts),
        "mitre": calculate_mitre_score(alerts),
    }

    total_score = min(sum(breakdown.values()), 90)

    return {
        "score": total_score,
        "priority": classify_incident_priority(total_score),
        "breakdown": breakdown,
    }