
from database.models import (
    initialize_db,
    get_cached_enrichment,
    save_cached_enrichment
)


def test_save_and_retrieve_cached_enrichment(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    data = {
        "malicious": 3,
        "harmless": 50
    }

    save_cached_enrichment(
        "198.51.100.25",
        "ip",
        "virustotal",
        data,
        db_path
    )

    result = get_cached_enrichment(
        "198.51.100.25",
        "ip",
        "virustotal",
        db_path
    )

    assert result == data


def test_cache_returns_none_for_missing_indicator(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    result = get_cached_enrichment(
        "example.com",
        "domain",
        "virustotal",
        db_path
    )

    assert result is None


def test_cache_expires(tmp_path):
    from datetime import timedelta

    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    save_cached_enrichment(
        "198.51.100.25",
        "ip",
        "virustotal",
        {"malicious": 2},
        db_path,
        ttl_hours=-1
    )

    result = get_cached_enrichment(
        "198.51.100.25",
        "ip",
        "virustotal",
        db_path
    )

    assert result is None


def test_cache_separates_providers(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_db(db_path)

    save_cached_enrichment(
        "198.51.100.25",
        "ip",
        "virustotal",
        {"malicious": 2},
        db_path
    )

    result = get_cached_enrichment(
        "198.51.100.25",
        "ip",
        "otx",
        db_path
    )

    assert result is None
