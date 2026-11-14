
import sqlite3
import json
from pathlib import Path
import hashlib

DEFAULT_DB_PATH = Path("database/threatlens.db")


def get_connection(db_path=DEFAULT_DB_PATH):
    """Create a connection to the ThreatLens database."""

    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_db(db_path=DEFAULT_DB_PATH):
    """Create the events table and indexes if they don't exist."""

    with get_connection(db_path) as connection:

        connection.executescript("""
            CREATE TABLE IF NOT EXISTS events (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source TEXT NOT NULL,
                host TEXT NOT NULL,

                username TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                process TEXT,
                command_line TEXT,
                status TEXT,
                fingerprint TEXT UNIQUE NOT NULL,
                raw_event TEXT NOT NULL,

                ingested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_event_timestamp
            ON events(timestamp);

            CREATE INDEX IF NOT EXISTS idx_event_type
            ON events(event_type);

            CREATE INDEX IF NOT EXISTS idx_event_source_ip
            ON events(source_ip);


            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT UNIQUE NOT NULL,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                username TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                process TEXT,
                command_line TEXT,
                mitre_tactic TEXT,
                mitre_technique_id TEXT,
                mitre_technique TEXT,
                evidence_json TEXT NOT NULL,
                enrichment_json TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
        """)



def insert_events(events, db_path=DEFAULT_DB_PATH):
    """Insert normalized security events into SQLite without duplicates."""

    if not events:
        return 0

    columns = [
        "timestamp",
        "event_type",
        "source",
        "host",
        "username",
        "source_ip",
        "destination_ip",
        "process",
        "command_line",
        "status"
    ]

    query = """
        INSERT OR IGNORE INTO events (
            fingerprint,
            timestamp,
            event_type,
            source,
            host,
            username,
            source_ip,
            destination_ip,
            process,
            command_line,
            status,
            raw_event
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    records = []

    for event in events:

        raw_json = json.dumps(
            event.get("raw_event", event),
            sort_keys=True
        )

        fingerprint = hashlib.sha256(
            raw_json.encode("utf-8")
        ).hexdigest()

        values = [event.get(column) for column in columns]

        records.append((
            fingerprint,
            *values,
            raw_json
        ))

    with get_connection(db_path) as connection:

        cursor = connection.executemany(query, records)

        inserted_count = cursor.rowcount

    return inserted_count



def get_events(db_path=DEFAULT_DB_PATH):
    """Retrieve all stored security events."""

    with get_connection(db_path) as connection:

        rows = connection.execute(
            "SELECT * FROM events ORDER BY id"
        ).fetchall()

    return [dict(row) for row in rows]


def get_event_count(db_path=DEFAULT_DB_PATH):
    """Return the total number of stored events."""

    with get_connection(db_path) as connection:

        result = connection.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()

    return result[0]


def save_alerts(alerts, db_path):
    connection = get_connection(db_path)

    query = """
        INSERT OR IGNORE INTO alerts (
            fingerprint,
            rule_id,
            rule_name,
            severity,
            description,
            username,
            source_ip,
            destination_ip,
            process,
            command_line,
            mitre_tactic,
            mitre_technique_id,
            mitre_technique,
            evidence_json,
            enrichment_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    records = []

    for alert in alerts:
        evidence = alert.get("evidence", [])

        fingerprint_data = (
            alert["rule_id"] + ":" +
            ",".join(map(str, sorted(evidence)))
        )

        fingerprint = hashlib.sha256(
            fingerprint_data.encode("utf-8")
        ).hexdigest()

        mitre = alert.get("mitre_attack") or {}

        records.append((
            fingerprint,
            alert["rule_id"],
            alert["rule_name"],
            alert["severity"],
            alert.get("description"),
            alert.get("username"),
            alert.get("source_ip"),
            alert.get("destination_ip"),
            alert.get("process"),
            alert.get("command_line"),
            mitre.get("tactic"),
            mitre.get("technique_id"),
            mitre.get("technique"),
            json.dumps(evidence),
            json.dumps(alert.get("threat_intelligence"))
        ))

    try:
        connection.executemany(query, records)
        connection.commit()
    finally:
        connection.close()



def get_alerts(db_path):
    connection = get_connection(db_path)

    try:
        rows = connection.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC"
        ).fetchall()

        results = []

        for row in rows:
            alert = dict(row)
            alert["evidence"] = json.loads(alert.pop("evidence_json"))
            alert["threat_intelligence"] = json.loads(
                alert.pop("enrichment_json")
            )
            results.append(alert)

        return results
    finally:
        connection.close()