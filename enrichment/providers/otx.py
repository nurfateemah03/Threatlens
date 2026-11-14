
import os
import requests

from dotenv import load_dotenv
from urllib.parse import quote

load_dotenv()

BASE_URL = "https://otx.alienvault.com/api/v1"
TIMEOUT = 15


class OTXError(Exception):
    """Raised when an OTX lookup fails."""
    pass


def lookup_indicator(indicator, indicator_type, api_key=None):
    """
    Look up an indicator using AlienVault OTX.

    Supported types: ip, domain, file_hash.
    """

    indicator_types = {
        "ip": "IPv4",
        "domain": "domain",
        "file_hash": "file"
    }

    if indicator_type not in indicator_types:
        raise ValueError("Unsupported indicator type")

    api_key = api_key or os.getenv("OTX_API_KEY")

    if not api_key:
        raise OTXError("OTX API key is missing")

    otx_type = indicator_types[indicator_type]

    safe_indicator = quote(indicator, safe="")

    url = (
        f"{BASE_URL}/indicators/"
        f"{otx_type}/{safe_indicator}/general"
    )

    headers = {
        "X-OTX-API-KEY": api_key
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
            raise OTXError("Indicator not found") from error

        if status_code == 429:
            raise OTXError("OTX rate limit reached") from error

        raise OTXError(
            f"OTX returned HTTP {status_code}"
        ) from error

    except requests.exceptions.Timeout as error:
        raise OTXError("OTX request timed out") from error

    except requests.exceptions.RequestException as error:
        raise OTXError(
            f"OTX connection failed: {error}"
        ) from error

    except ValueError as error:
        raise OTXError("Invalid JSON response from OTX") from error


def summarize_report(report):
    """Extract useful threat intelligence from an OTX response."""

    try:
        data = report["pulse_info"]
    except (KeyError, TypeError):
        raise ValueError("Invalid OTX report structure")

    pulses = data.get("pulses", [])

    return {
        "pulse_count": data.get("count", 0),
        "pulse_names": [
            pulse.get("name")
            for pulse in pulses
            if pulse.get("name")
        ]
    }
