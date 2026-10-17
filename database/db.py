
import sqlite3
import json
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = PROJECT_DIR / "database" / "scanner.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scanned_at TEXT NOT NULL DEFAULT
                    (datetime('now', 'localtime')),
                status_code INTEGER,
                findings_count INTEGER NOT NULL DEFAULT 0,
                scan_result TEXT NOT NULL,
                error TEXT
            )
        """)


def save_scan(target_url, result):
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO scan_history (
                target_url,
                status_code,
                findings_count,
                scan_result,
                error
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                target_url,
                result.get("status_code"),
                len(result.get("findings", [])),
                json.dumps(result),
                result.get("error")
            )
        )


def get_scan_history():
    connection = get_connection()

    try:
        records = connection.execute("""
            SELECT
                id,
                target_url,
                scanned_at,
                status_code,
                findings_count,
                error
            FROM scan_history
            ORDER BY id DESC
        """).fetchall()

        return records

    finally:
        connection.close()



def clear_scan_history():
    with get_connection() as connection:
        connection.execute("DELETE FROM scan_history")



def delete_scan(scan_id):
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM scan_history WHERE id = ?",
            (scan_id,)
        )



if __name__ == "__main__":
    initialize_database()
    print("Database initialized successfully.")
    print(f"Database location: {DATABASE_PATH}")