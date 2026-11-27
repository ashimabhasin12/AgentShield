
import sqlite3

from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4
from contextlib import closing


DB_PATH = Path(__file__).resolve().parent / "agentshield.db"


def initialize_database():

    with closing(sqlite3.connect(DB_PATH)) as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                request_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                tool TEXT NOT NULL,
                event_type TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT,
                approval_id TEXT
            )
        """)

        conn.commit()


def log_event(
    request_id,
    action,
    event_type,
    decision,
    reason="",
    approval_id=None
):

    initialize_database()

    event_id = str(uuid4())

    timestamp = datetime.now(timezone.utc).isoformat()

    with closing(sqlite3.connect(DB_PATH)) as conn:

        conn.execute("""
            INSERT INTO audit_logs (
                event_id,
                request_id,
                timestamp,
                tool,
                event_type,
                decision,
                reason,
                approval_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_id,
            request_id,
            timestamp,
            action.get("tool", "unknown"),
            event_type,
            decision,
            reason,
            approval_id
        ))

        conn.commit()

    return event_id


def view_logs():

    initialize_database()

    with closing(sqlite3.connect(DB_PATH)) as conn:

        conn.row_factory = sqlite3.Row

        records = conn.execute("""
            SELECT * FROM audit_logs
            ORDER BY id DESC
        """).fetchall()

        return [dict(row) for row in records]


def get_statistics():

    initialize_database()

    with closing(sqlite3.connect(DB_PATH)) as conn:

        records = conn.execute("""
            SELECT decision, COUNT(*)
            FROM audit_logs
            WHERE event_type = 'POLICY'
            GROUP BY decision
        """).fetchall()

        stats = {
            "ALLOW": 0,
            "BLOCK": 0,
            "REVIEW": 0
        }

        stats.update(dict(records))

        stats["TOTAL"] = sum(
            stats[key]
            for key in ("ALLOW", "BLOCK", "REVIEW")
        )

        return stats


if __name__ == "__main__":

    import json

    initialize_database()

    print("=" * 50)

    print("AGENTSHIELD SECURITY AUDIT DATABASE")

    print("=" * 50)

    print("Database initialized successfully.")

    print("Database location:", DB_PATH)

    print("\nSECURITY STATISTICS")

    print(json.dumps(get_statistics(), indent=4))

    print("\nAUDIT LOGS")

    print(json.dumps(view_logs(), indent=4))
