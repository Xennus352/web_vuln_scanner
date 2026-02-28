import os
import sqlite3


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vuln_lab.db")


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            secret_bio TEXT NOT NULL
        )
        """
    )

    cur.execute("DELETE FROM users")
    cur.executemany(
        "INSERT INTO users (username, password, secret_bio) VALUES (?, ?, ?)",
        [
            ("alice", "alice123", "Alice secret: Recovery code is ALICE-001."),
            ("bob", "bob123", "Bob secret: Internal API key draft is BOB-DEV-KEY."),
            ("charlie", "charlie123", "Charlie secret: Finance note is in /vault/charlie."),
        ],
    )

    conn.commit()
    conn.close()
    print(f"Initialized database at: {DB_PATH}")


if __name__ == "__main__":
    init_db()
