"""backend/db.py: SQLite persistence for PIDS authentication and user management."""
import datetime as dt
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "auth.db"

ROLES = {"admin", "analyst", "viewer"}


def get_connection() -> sqlite3.Connection:
    """Return a connection with Row factory enabled."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize user management table."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                hashed_password TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'analyst', 'viewer')),
                full_name TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        conn.commit()


def get_user_by_username(username: str, active_only: bool = True) -> Optional[Dict[str, Any]]:
    """Lookup user by case-insensitive username."""
    query = "SELECT * FROM users WHERE username = ?"
    if active_only:
        query += " AND is_active = 1"
    with get_connection() as conn:
        cur = conn.execute(query, (username.strip(),))
        row = cur.fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Lookup active user by ID."""
    with get_connection() as conn:
        cur = conn.execute(
            "SELECT * FROM users WHERE id = ? AND is_active = 1",
            (user_id,)
        )
        row = cur.fetchone()
        return dict(row) if row else None


def create_user(username: str, hashed_password: str, role: str, full_name: str) -> int:
    """Insert a new user record. Returns new user id."""
    role = role.lower().strip()
    if role not in ROLES:
        raise ValueError(f"Invalid role '{role}'. Must be one of {ROLES}")

    now = dt.datetime.now(dt.timezone.utc).isoformat()
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO users (username, hashed_password, role, full_name, is_active, created_at)
            VALUES (?, ?, ?, ?, 1, ?)
            ON CONFLICT(username) DO UPDATE SET
                hashed_password = excluded.hashed_password,
                role = excluded.role,
                full_name = excluded.full_name,
                is_active = 1
            """,
            (username.strip().lower(), hashed_password, role, full_name.strip(), now)
        )
        conn.commit()
        return cur.lastrowid


def list_users() -> List[Dict[str, Any]]:
    """List all active users without exposing password hashes."""
    with get_connection() as conn:
        cur = conn.execute(
            """
            SELECT id, username, role, full_name, is_active, created_at, last_login
            FROM users
            WHERE is_active = 1
            ORDER BY id ASC
            """
        )
        return [dict(r) for r in cur.fetchall()]


def update_last_login(user_id: int) -> None:
    """Record login timestamp."""
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, user_id))
        conn.commit()


def delete_user(user_id: int) -> bool:
    """Delete user from database."""
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return cur.rowcount > 0


# Ensure database is initialized on module import
init_db()
