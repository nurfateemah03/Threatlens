
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

                        CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open'
                    CHECK (
                        status IN (
                            'open',
                            'investigating',
                            'resolved',
                            'false_positive'
                        )
                    ),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                resolved_at TEXT
            );

            CREATE TABLE IF NOT EXISTS incident_alerts (
                incident_id INTEGER NOT NULL,
                alert_id INTEGER NOT NULL,
                linked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

                PRIMARY KEY (incident_id, alert_id),

                FOREIGN KEY (incident_id)
                    REFERENCES incidents(id) ON DELETE CASCADE,

                FOREIGN KEY (alert_id)
                    REFERENCES alerts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS incident_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                note TEXT NOT NULL,
                priority_score INTEGER NOT NULL DEFAULT 0,
                priority TEXT NOT NULL DEFAULT 'low',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (incident_id)
                    REFERENCES incidents(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_incident_status
                ON incidents(status);

            CREATE INDEX IF NOT EXISTS idx_incident_severity
                ON incidents(severity);

            CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert_id
                ON incident_alerts(alert_id);

            CREATE INDEX IF NOT EXISTS idx_incident_notes_incident_id
                ON incident_notes(incident_id);

            CREATE TABLE IF NOT EXISTS incident_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                activity_type TEXT NOT NULL,
                description TEXT NOT NULL,
                old_status TEXT,
                new_status TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id)
                    REFERENCES incidents(id)
                    ON DELETE CASCADE
);
        """)
        incident_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(incidents)"
            ).fetchall()
        }

        if "priority_score" not in incident_columns:
            connection.execute("""
                ALTER TABLE incidents
                ADD COLUMN priority_score INTEGER NOT NULL DEFAULT 0
            """)

        if "priority" not in incident_columns:
            connection.execute("""
                ALTER TABLE incidents
                ADD COLUMN priority TEXT NOT NULL DEFAULT 'low'
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
                "external": alert.get("external_intelligence"),
                "behavioral_context": alert.get(
                    "behavioral_context"
                ),
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

def create_incident(
    fingerprint,
    title,
    severity,
    description=None,
    db_path=DEFAULT_DB_PATH
):
    with get_connection(db_path) as connection:
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO incidents (
                fingerprint,
                title,
                description,
                severity
            )
            VALUES (?, ?, ?, ?)
            """,
            (fingerprint, title, description, severity)
        )

        row = connection.execute(
            """
            SELECT * FROM incidents
            WHERE fingerprint = ?
            """,
            (fingerprint,)
        ).fetchone()

        incident = dict(row)

        # Record creation only when a new incident was inserted.
        if cursor.rowcount > 0:
            connection.execute(
                """
                INSERT INTO incident_history (
                    incident_id,
                    activity_type,
                    description
                )
                VALUES (?, ?, ?)
                """,
                (
                    incident["id"],
                    "created",
                    "Incident created from correlated security alerts."
                )
            )

    return incident

def link_alert_to_incident(
    incident_id,
    alert_id,
    db_path=DEFAULT_DB_PATH
):
    with get_connection(db_path) as connection:
        connection.execute(
            """
            INSERT OR IGNORE INTO incident_alerts (
                incident_id,
                alert_id
            )
            VALUES (?, ?)
            """,
            (incident_id, alert_id)
        )

def add_incident_note(
    incident_id,
    note,
    db_path=DEFAULT_DB_PATH
):
    if not note or not note.strip():
        raise ValueError("Note cannot be empty")

    with get_connection(db_path) as connection:

        # Verify that the incident exists.
        incident = connection.execute(
            """
            SELECT id FROM incidents
            WHERE id = ?
            """,
            (incident_id,)
        ).fetchone()

        if incident is None:
            raise ValueError(f"Incident {incident_id} not found")

        cursor = connection.execute(
            """
            INSERT INTO incident_notes (
                incident_id,
                note
            )
            VALUES (?, ?)
            """,
            (incident_id, note.strip())
        )

        note_id = cursor.lastrowid

        # Record that an analyst added a note.
        connection.execute(
            """
            INSERT INTO incident_history (
                incident_id,
                activity_type,
                description
            )
            VALUES (?, ?, ?)
            """,
            (
                incident_id,
                "note_added",
                "An analyst added an investigation note."
            )
        )

    return note_id

def get_incident_notes(
    incident_id,
    db_path=DEFAULT_DB_PATH
):
    with get_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM incident_notes
            WHERE incident_id = ?
            ORDER BY created_at ASC, id ASC
            """,
            (incident_id,)
        ).fetchall()

    return [dict(row) for row in rows]
def get_incidents(db_path=DEFAULT_DB_PATH):
    with get_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT
                i.*,
                COUNT(ia.alert_id) AS alert_count
            FROM incidents i
            LEFT JOIN incident_alerts ia
                ON i.id = ia.incident_id
            GROUP BY i.id
            ORDER BY i.created_at DESC
            """
        ).fetchall()

    return [dict(row) for row in rows]

def update_incident_status(
    incident_id,
    new_status,
    db_path=DEFAULT_DB_PATH
):
    valid_statuses = {
        "open",
        "investigating",
        "resolved",
        "false_positive"
    }

    if new_status not in valid_statuses:
        raise ValueError(f"Invalid incident status: {new_status}")

    with get_connection(db_path) as connection:

        # Retrieve the current status before updating.
        incident = connection.execute(
            """
            SELECT * FROM incidents
            WHERE id = ?
            """,
            (incident_id,)
        ).fetchone()

        if incident is None:
            raise ValueError(f"Incident {incident_id} not found")

        old_status = incident["status"]

        # Only update and record an activity if status changed.
        if old_status != new_status:

            connection.execute(
                """
                UPDATE incidents
                SET
                    status = ?,
                    updated_at = CURRENT_TIMESTAMP,
                    resolved_at = CASE
                        WHEN ? IN ('resolved', 'false_positive')
                        THEN CURRENT_TIMESTAMP
                        ELSE NULL
                    END
                WHERE id = ?
                """,
                (new_status, new_status, incident_id)
            )

            connection.execute(
                """
                INSERT INTO incident_history (
                    incident_id,
                    activity_type,
                    description,
                    old_status,
                    new_status
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    "status_changed",
                    f"Incident status changed from {old_status} to {new_status}.",
                    old_status,
                    new_status
                )
            )

        updated_incident = connection.execute(
            """
            SELECT * FROM incidents
            WHERE id = ?
            """,
            (incident_id,)
        ).fetchone()

    return dict(updated_incident)

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

def merge_incidents(
    source_id,
    target_id,
    db_path=DEFAULT_DB_PATH
):
    if source_id == target_id:
        raise ValueError("Cannot merge an incident into itself")

    with get_connection(db_path) as connection:

        source = connection.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (source_id,)
        ).fetchone()

        target = connection.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (target_id,)
        ).fetchone()

        if source is None or target is None:
            raise ValueError("Source or target incident not found")

        # Move alert relationships to the target incident.
        connection.execute(
            """
            INSERT OR IGNORE INTO incident_alerts (
                incident_id,
                alert_id,
                linked_at
            )
            SELECT ?, alert_id, linked_at
            FROM incident_alerts
            WHERE incident_id = ?
            """,
            (target_id, source_id)
        )

        # Preserve investigation notes.
        connection.execute(
            """
            INSERT INTO incident_notes (
                incident_id,
                note,
                created_at
            )
            SELECT ?, note, created_at
            FROM incident_notes
            WHERE incident_id = ?
            """,
            (target_id, source_id)
        )

        # Keep whichever incident has the higher severity.
        connection.execute(
            """
            UPDATE incidents
            SET
                severity = CASE
                    WHEN
                        CASE severity
                            WHEN 'critical' THEN 4
                            WHEN 'high' THEN 3
                            WHEN 'medium' THEN 2
                            WHEN 'low' THEN 1
                            ELSE 0
                        END
                    <
                        CASE ?
                            WHEN 'critical' THEN 4
                            WHEN 'high' THEN 3
                            WHEN 'medium' THEN 2
                            WHEN 'low' THEN 1
                            ELSE 0
                        END
                    THEN ?
                    ELSE severity
                END,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (source["severity"], source["severity"], target_id)
        )
        connection.execute(
                """
                INSERT INTO incident_history (
                    incident_id,
                    activity_type,
                    description,
                    old_status,
                    new_status,
                    created_at
                )
                SELECT
                    ?,
                    activity_type,
                    description,
                    old_status,
                    new_status,
                    created_at
                FROM incident_history
                WHERE incident_id = ?
                """,
                (target_id, source_id)
            )

        connection.execute(
                """
                INSERT INTO incident_history (
                    incident_id,
                    activity_type,
                    description
                )
                VALUES (?, ?, ?)
                """,
                (
                    target_id,
                    "incident_merged",
                    f"Incident #{source_id} was merged into this incident."
                )
            )

        # Delete the provisional incident.
        connection.execute(
            "DELETE FROM incidents WHERE id = ?",
            (source_id,)
        )

        result = connection.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (target_id,)
        ).fetchone()

    return dict(result)

def get_incident_alerts(
    incident_id,
    db_path=DEFAULT_DB_PATH
):
    with get_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT a.*
            FROM alerts a
            JOIN incident_alerts ia
                ON a.id = ia.alert_id
            WHERE ia.incident_id = ?
            ORDER BY a.created_at ASC
            """,
            (incident_id,)
        ).fetchall()

    return [dict(row) for row in rows]
def update_incident_priority(
    incident_id,
    priority_score,
    priority,
    db_path=DEFAULT_DB_PATH
):
    """Persist an incident's calculated score and priority."""

    valid_priorities = {
        "low",
        "medium",
        "high",
        "critical"
    }

    if priority not in valid_priorities:
        raise ValueError("Invalid incident priority")

    if not isinstance(priority_score, int) or not 0 <= priority_score <= 90:
        raise ValueError("Priority score must be between 0 and 90")

    with get_connection(db_path) as connection:
        cursor = connection.execute(
            """
            UPDATE incidents
            SET
                priority_score = ?,
                priority = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (priority_score, priority, incident_id)
        )

        if cursor.rowcount == 0:
            raise ValueError(f"Incident {incident_id} does not exist")

        row = connection.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,)
        ).fetchone()

    return dict(row)

def record_incident_activity(
    incident_id,
    activity_type,
    description,
    old_status=None,
    new_status=None,
    db_path=DEFAULT_DB_PATH
):
    with get_connection(db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO incident_history (
                incident_id,
                activity_type,
                description,
                old_status,
                new_status
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                activity_type,
                description,
                old_status,
                new_status
            )
        )

        return cursor.lastrowid


def get_incident_timeline(
    incident_id,
    db_path=DEFAULT_DB_PATH
):
    with get_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM incident_history
            WHERE incident_id = ?
            ORDER BY created_at ASC, id ASC
            """,
            (incident_id,)
        ).fetchall()

        return [dict(row) for row in rows]

def get_alert_evidence_events(
    alert_id,
    db_path=DEFAULT_DB_PATH
):
    """Retrieve the original events associated with an alert."""

    with get_connection(db_path) as connection:

        alert = connection.execute(
            """
            SELECT evidence_json
            FROM alerts
            WHERE id = ?
            """,
            (alert_id,)
        ).fetchone()

        if alert is None:
            return []

        try:
            evidence_ids = json.loads(
                alert["evidence_json"] or "[]"
            )
        except (TypeError, json.JSONDecodeError):
            return []

        if not evidence_ids:
            return []

        # Only use valid integer event IDs.
        try:
            evidence_ids = list(dict.fromkeys(
                int(event_id) for event_id in evidence_ids
            ))
        except (TypeError, ValueError):
            return []

        placeholders = ",".join(
            "?" for _ in evidence_ids
        )

        rows = connection.execute(
            f"""
            SELECT *
            FROM events
            WHERE id IN ({placeholders})
            """,
            evidence_ids
        ).fetchall()

        events_by_id = {
            row["id"]: dict(row)
            for row in rows
        }

        # Preserve the original evidence order.
        return [
            events_by_id[event_id]
            for event_id in evidence_ids
            if event_id in events_by_id
        ]
