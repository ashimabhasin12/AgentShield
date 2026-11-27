
import sqlite3
from pathlib import Path
from contextlib import contextmanager

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "agentshield.db"


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def initialize_database():

    with get_db() as conn:

        conn.executescript("""

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'employee'
                CHECK(role IN ('admin', 'employee', 'viewer')),
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT DEFAULT 'New Conversation',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(conversation_id)
                REFERENCES conversations(id)
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            conversation_id INTEGER,
            instruction TEXT NOT NULL,
            tool_name TEXT,
            parameters TEXT,
            status TEXT DEFAULT 'PENDING',
            security_decision TEXT,
            result TEXT,
            error_message TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            completed_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(conversation_id)
                REFERENCES conversations(id)
        );

        CREATE TABLE IF NOT EXISTS approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            requested_by INTEGER NOT NULL,
            reviewed_by INTEGER,
            action_payload TEXT NOT NULL,
            status TEXT DEFAULT 'PENDING'
                CHECK(status IN (
                    'PENDING', 'APPROVED', 'REJECTED',
                    'EXPIRED', 'CONSUMED'
                )),
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            reviewed_at TEXT,
            FOREIGN KEY(task_id) REFERENCES tasks(id),
            FOREIGN KEY(requested_by) REFERENCES users(id),
            FOREIGN KEY(reviewed_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            file_type TEXT,
            sensitivity TEXT DEFAULT 'PRIVATE',
            file_size INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS client_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_name TEXT UNIQUE NOT NULL,
            description TEXT,
            role TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            decision TEXT NOT NULL
                CHECK(decision IN ('ALLOW', 'BLOCK', 'REVIEW')),
            conditions TEXT DEFAULT '{}',
            enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS integrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            service_name TEXT NOT NULL,
            account_email TEXT,
            credential_reference TEXT,
            connection_status TEXT DEFAULT 'DISCONNECTED',
            connected_at TEXT,
            UNIQUE(user_id, service_name),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS workflows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            workflow_name TEXT NOT NULL,
            instruction TEXT NOT NULL,
            execution_plan TEXT,
            status TEXT DEFAULT 'PENDING',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            completed_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS workflow_steps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workflow_id INTEGER NOT NULL,
            step_number INTEGER NOT NULL,
            tool_name TEXT NOT NULL,
            parameters TEXT,
            security_decision TEXT,
            status TEXT DEFAULT 'PENDING',
            result TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(workflow_id, step_number),
            FOREIGN KEY(workflow_id) REFERENCES workflows(id)
        );

        CREATE TABLE IF NOT EXISTS experiments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            experiment_name TEXT NOT NULL,
            model_name TEXT,
            dataset_name TEXT,
            security_approach TEXT,
            status TEXT DEFAULT 'PENDING',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS benchmark_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            experiment_id INTEGER NOT NULL,
            test_case TEXT NOT NULL,
            expected_decision TEXT,
            actual_decision TEXT,
            task_success INTEGER,
            attack_success INTEGER,
            latency_ms REAL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(experiment_id)
                REFERENCES experiments(id)
        );

        CREATE INDEX IF NOT EXISTS idx_client_tasks_user
        ON tasks(user_id);

        CREATE INDEX IF NOT EXISTS idx_client_messages_conversation
        ON messages(conversation_id);

        CREATE INDEX IF NOT EXISTS idx_client_approvals_status
        ON approvals(status);

        """)

    print("=" * 55)
    print("AGENTSHIELD DATABASE INITIALIZED SUCCESSFULLY")
    print("=" * 55)
    print(f"Database location: {DB_PATH}")


def show_tables():

    with get_db() as conn:

        tables = conn.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            ORDER BY name
        """).fetchall()

        print("\nDATABASE TABLES")
        print("-" * 40)

        for table in tables:
            print("[OK]", table["name"])

        print("-" * 40)
        print("Total tables:", len(tables))


if __name__ == "__main__":
    initialize_database()
    show_tables()
