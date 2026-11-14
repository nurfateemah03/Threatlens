
from pathlib import Path

from ingestion.parser import parse_jsonl
from ingestion.normalizer import normalize_event
from database.models import initialize_db, insert_events


def ingest_file(file_path, db_path=None):
    """
    Read a JSONL file, parse and normalize events,
    then store them in SQLite.
    """

    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Event file not found: {file_path}"
        )

    raw_data = file_path.read_text(encoding="utf-8")

    # Stage 1: Parse incoming JSON events.
    raw_events = parse_jsonl(raw_data)

    # Stage 2: Normalize each event.
    normalized_events = []

    for raw_event in raw_events:

        normalized = normalize_event(raw_event)

        # Preserve the original event separately.
        normalized["raw_event"] = raw_event

        normalized_events.append(normalized)

    # Stage 3: Initialize database.
    if db_path is None:
        initialize_db()
    else:
        initialize_db(db_path)

    # Stage 4: Store normalized events.
    if db_path is None:
        stored_count = insert_events(normalized_events)
    else:
        stored_count = insert_events(
            normalized_events,
            db_path
        )

    return {
        "events_received": len(raw_events),
        "events_normalized": len(normalized_events),
        "events_stored": stored_count
    }
