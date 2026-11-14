
import sqlite3
import json
from pathlib import Path
import hashlib
from datetime import datetime, timedelta, timezone

DEFAULT_DB_PATH = Path("database/threatlens.db")


def get_connection(db_path=DEFAULT_DB_PATH):
    """Create a connection to the ThreatLens database."""

    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_db(db_path=DEFAULT_DB_PATH):
    """Create the events, alerts, and indicator cache tables and indexes."""

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

            CREATE TABLE IF NOT EXISTS indicator_cache (
                indicator TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                provider TEXT NOT NULL,
                data_json TEXT NOT NULL,
                cached_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY (indicator, indicator_type, provider)
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
            json.dumps({
                "local": alert.get("threat_intelligence"),
               "external": alert.get("external_intelligence")
})
        ))

    try:
        connection.executemany(query, records)
        connection.commit()
    finally:
        connection.close()




def get_alerts(db_path=DEFAULT_DB_PATH):
    with get_connection(db_path) as connection:
        rows = connection.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC"
        ).fetchall()

    alerts = []

    for row in rows:
        alert = dict(row)

        alert["evidence"] = json.loads(
            alert.pop("evidence_json") or "[]"
        )

        alert["enrichment_json"] = json.loads(
            alert.get("enrichment_json") or "null"
        )

        alerts.append(alert)

    return alerts


        
def get_cached_enrichment(
    indicator,
    indicator_type,
    provider,
    db_path=DEFAULT_DB_PATH
):
    """Retrieve an unexpired intelligence result from SQLite."""

    now = datetime.now(timezone.utc).isoformat()

    with get_connection(db_path) as connection:
        row = connection.execute(
            """
            SELECT data_json
            FROM indicator_cache
            WHERE indicator = ?
              AND indicator_type = ?
              AND provider = ?
              AND expires_at > ?
            """,
            (indicator, indicator_type, provider, now)
        ).fetchone()

    if row is None:
        return None

    return json.loads(row["data_json"])


def save_cached_enrichment(
    indicator,
    indicator_type,
    provider,
    data,
    db_path=DEFAULT_DB_PATH,
    ttl_hours=24
):
    """Store successful intelligence results with an expiry time."""

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=ttl_hours)

    with get_connection(db_path) as connection:
        connection.execute(
            """
            INSERT INTO indicator_cache (
                indicator,
                indicator_type,
                provider,
                data_json,
                cached_at,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(indicator, indicator_type, provider)
            DO UPDATE SET
                data_json = excluded.data_json,
                cached_at = excluded.cached_at,
                expires_at = excluded.expires_at
            """,
            (
                indicator,
                indicator_type,
                provider,
                json.dumps(data),
                now.isoformat(),
                expires_at.isoformat()
            )
        )
