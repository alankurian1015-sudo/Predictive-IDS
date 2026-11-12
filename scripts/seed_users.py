"""scripts/seed_users.py: Seed initial SOC users (admin, analyst, viewer) into PIDS SQLite database."""
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend import auth, db

DEFAULT_USERS = [
    {
        "username": "admin",
        "password": "admin123",
        "role": "admin",
        "full_name": "SOC Administrator",
    },
    {
        "username": "analyst",
        "password": "analyst123",
        "role": "analyst",
        "full_name": "SOC Threat Analyst",
    },
    {
        "username": "viewer",
        "password": "viewer123",
        "role": "viewer",
        "full_name": "Security Auditor",
    },
]


def seed():
    print("=" * 65)
    print(" PIDS Authentication Seeder")
    print("=" * 65)
    db.init_db()

    for u in DEFAULT_USERS:
        existing = db.get_user_by_username(u["username"])
        if existing:
            print(f" [SKIP] User '{u['username']}' already exists (Role: {existing['role']}).")
        else:
            hashed = auth.hash_password(u["password"])
            uid = db.create_user(u["username"], hashed, u["role"], u["full_name"])
            print(f" [OK]   Created user '{u['username']}' (ID: {uid}, Role: {u['role']})")

    print("-" * 65)
    print("Default Credentials Available for Testing:")
    print("  • Admin:   Username: admin   | Password: admin123   (Full Control)")
    print("  • Analyst: Username: analyst | Password: analyst123 (Alert Triage & SHAP)")
    print("  • Viewer:  Username: viewer  | Password: viewer123  (Read-Only Telemetry)")
    print("=" * 65)


if __name__ == "__main__":
    seed()
