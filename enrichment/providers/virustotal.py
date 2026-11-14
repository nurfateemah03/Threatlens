
import os
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

BASE_URL = "https://www.virustotal.com/api/v3"

TIMEOUT = 15


class VirusTotalError(Exception):
    """Raised when a VirusTotal lookup fails."""
    pass


def lookup_indicator(indicator, indicator_type, api_key=None):
    """
    Look up an IP, domain, or file hash using VirusTotal.

    indicator_type must be: ip, domain, or file_hash.
    """

    if indicator_type not in ("ip", "domain", "file_hash"):
        raise ValueError("Unsupported indicator type")

    api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        raise VirusTotalError("VirusTotal API key is missing")

    endpoint_types = {
        "ip": "ip_addresses",
        "domain": "domains",
        "file_hash": "files"
    }

    url = f"{BASE_URL}/{endpoint_types[indicator_type]}/{indicator}"

    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=TIMEOUT
        )

        response.raise_for_status()

        return response.json()

    except requests.exceptions.HTTPError as error:
        status_code = error.response.status_code

        if status_code == 404:
            raise VirusTotalError("Indicator not found") from error

        if status_code == 429:
            raise VirusTotalError("VirusTotal API rate limit reached") from error

        raise VirusTotalError(
            f"VirusTotal returned HTTP {status_code}"
        ) from error

    except requests.exceptions.Timeout as error:
        raise VirusTotalError("VirusTotal request timed out") from error

    except requests.exceptions.RequestException as error:
        raise VirusTotalError(
            f"VirusTotal connection failed: {error}"
        ) from error

    except ValueError as error:
        raise VirusTotalError("Invalid JSON response from VirusTotal") from error


def summarize_report(report):
    """
    Extract useful threat intelligence fields
    from a VirusTotal API response.
    """

    try:
        data = report["data"]
        attributes = data["attributes"]
    except (KeyError, TypeError):
        raise ValueError("Invalid VirusTotal report structure")

    stats = attributes.get("last_analysis_stats", {})

    analysis_stats = {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "timeout": stats.get("timeout", 0)
    }

    analysis_timestamp = attributes.get("last_analysis_date")

    if analysis_timestamp:
        analysis_date = datetime.fromtimestamp(
            analysis_timestamp,
            tz=timezone.utc
        ).isoformat()
    else:
        analysis_date = None

    return {
        "indicator": data.get("id"),
        "indicator_type": data.get("type"),
        "reputation": attributes.get("reputation", 0),
        "analysis_stats": analysis_stats,
        "total_engines": sum(analysis_stats.values()),
        "last_analysis_date": analysis_date
    }
