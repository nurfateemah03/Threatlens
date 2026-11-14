from pathlib import Path


IOC_PATH = Path("intelligence/ioc_list.txt")


def enrich_alert(alert):
    destination_ip = alert.get("destination_ip")

    if not destination_ip:
        alert["threat_intelligence"] = {
            "matched": False,
            "source": None
        }
        return alert

    with open(IOC_PATH, "r", encoding="utf-8") as file:
        indicators = {
            line.strip()
            for line in file
            if line.strip() and not line.strip().startswith("#")
        }

    matched = destination_ip in indicators

    alert["threat_intelligence"] = {
        "matched": matched,
        "indicator": destination_ip if matched else None,
        "source": "local_ioc_list" if matched else None,
        "classification": (
            "synthetic_test_indicator" if matched else None
        )
    }

    return alert