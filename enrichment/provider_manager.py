from database.models import (
    DEFAULT_DB_PATH,
    initialize_db,
    get_cached_enrichment,
    save_cached_enrichment
)

from enrichment.providers.virustotal import (
    lookup_indicator as vt_lookup,
    summarize_report as vt_summarize,
    VirusTotalError
)

from enrichment.providers.otx import (
    lookup_indicator as otx_lookup,
    summarize_report as otx_summarize,
    OTXError
)


def enrich_indicator(
    indicator,
    indicator_type,
    db_path=DEFAULT_DB_PATH
):
    initialize_db(db_path)
    """
    Query available providers and cache successful results.
    """

    results = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "providers": {}
    }

    providers = [
        ("virustotal", vt_lookup, vt_summarize, VirusTotalError),
        ("otx", otx_lookup, otx_summarize, OTXError)
    ]

    for name, lookup, summarize, error_type in providers:

        cached_data = get_cached_enrichment(
            indicator,
            indicator_type,
            name,
            db_path
        )

        if cached_data is not None:
            results["providers"][name] = {
                "status": "success",
                "cached": True,
                "data": cached_data
            }
            continue

        try:
            report = lookup(indicator, indicator_type)
            summary = summarize(report)

            save_cached_enrichment(
                indicator,
                indicator_type,
                name,
                summary,
                db_path
            )

            results["providers"][name] = {
                "status": "success",
                "cached": False,
                "data": summary
            }

        except (error_type, ValueError) as error:
            results["providers"][name] = {
                "status": "error",
                "error": str(error)
            }

    return results