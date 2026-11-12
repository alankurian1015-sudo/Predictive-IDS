"""tests/test_auth.py: Comprehensive test suite for PIDS Authentication & RBAC."""
import uuid
import pytest
from fastapi.testclient import TestClient

from backend import auth, db
from backend.server import app


@pytest.fixture(autouse=True)
def setup_users():
    """Ensure standard test users exist."""
    db.init_db()
    for username, pwd, role, full_name in [
        ("admin", "admin123", "admin", "SOC Administrator"),
        ("analyst", "analyst123", "analyst", "Threat Analyst"),
        ("viewer", "viewer123", "viewer", "Auditor"),
    ]:
        u = db.get_user_by_username(username)
        if not u:
            db.create_user(username, auth.hash_password(pwd), role, full_name)


@pytest.fixture
def client():
    return TestClient(app)


def test_login_success(client):
    res = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert res.status_code == 200
    data = res.json()
    assert data["ok"] is True
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "admin"
    assert "token" in data
    assert "pids_token" in res.cookies


def test_login_invalid_password(client):
    res = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert res.status_code == 401
    assert "Invalid username or password" in res.json()["detail"]


def test_login_nonexistent_user(client):
    res = client.post("/api/auth/login", json={"username": "nobody", "password": "password123"})
    assert res.status_code == 401


def test_unauthenticated_request_blocked(client):
    res = client.get("/api/state")
    assert res.status_code == 401

    res = client.post("/api/status", json={"event_id": 1, "status": "Acknowledged"})
    assert res.status_code == 401


def test_me_endpoint(client):
    res = client.post("/api/auth/login", json={"username": "analyst", "password": "analyst123"})
    assert res.status_code == 200

    me_res = client.get("/api/auth/me")
    assert me_res.status_code == 200
    me = me_res.json()
    assert me["user"]["username"] == "analyst"
    assert me["user"]["role"] == "analyst"


def test_rbac_viewer_restrictions(client):
    client.post("/api/auth/login", json={"username": "viewer", "password": "viewer123"})

    # Viewer CAN read telemetry state
    res = client.get("/api/state")
    assert res.status_code == 200

    # Viewer CANNOT triage alerts -> 403 Forbidden
    res = client.post("/api/status", json={"event_id": 1, "status": "Acknowledged"})
    assert res.status_code == 403
    assert "Access denied" in res.json()["detail"]

    # Viewer CANNOT change feed / controls -> 403 Forbidden
    res = client.post("/api/control", json={"rate": 10})
    assert res.status_code == 403

    # Viewer CANNOT manage users -> 403 Forbidden
    res = client.get("/api/auth/users")
    assert res.status_code == 403


def test_rbac_analyst_permissions(client):
    client.post("/api/auth/login", json={"username": "analyst", "password": "analyst123"})

    # Analyst CAN read telemetry
    assert client.get("/api/state").status_code == 200

    # Analyst CAN triage alerts
    assert client.post("/api/status", json={"event_id": 1, "status": "Acknowledged"}).status_code == 200

    # Analyst CANNOT control feed ingestion -> 403 Forbidden
    res = client.post("/api/control", json={"rate": 10})
    assert res.status_code == 403

    # Analyst CANNOT access user management -> 403 Forbidden
    assert client.get("/api/auth/users").status_code == 403


def test_rbac_admin_full_access(client):
    client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})

    # Admin CAN control feed
    assert client.post("/api/control", json={"rate": 25}).status_code == 200

    # Admin CAN access user list
    res = client.get("/api/auth/users")
    assert res.status_code == 200
    assert len(res.json()["users"]) >= 3


def test_admin_user_lifecycle(client):
    # Login as admin
    client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})

    # Generate unique test username
    unique_user = f"analyst_{uuid.uuid4().hex[:6]}"
    new_user = {
        "username": unique_user,
        "password": "Password99!",
        "role": "analyst",
        "full_name": "New SOC Analyst",
    }
    res = client.post("/api/auth/users", json=new_user)
    assert res.status_code == 200
    user_id = res.json()["user_id"]

    # Login as new user
    client_new = TestClient(app)
    login_res = client_new.post("/api/auth/login", json={"username": unique_user, "password": "Password99!"})
    assert login_res.status_code == 200
    assert login_res.json()["user"]["role"] == "analyst"

    # Admin deactivates user
    del_res = client.delete(f"/api/auth/users/{user_id}")
    assert del_res.status_code == 200

    # Deactivated user cannot log in
    failed_login = client_new.post("/api/auth/login", json={"username": unique_user, "password": "Password99!"})
    assert failed_login.status_code == 401


def test_logout(client):
    client.post("/api/auth/login", json={"username": "viewer", "password": "viewer123"})
    assert client.get("/api/state").status_code == 200

    logout_res = client.post("/api/auth/logout")
    assert logout_res.status_code == 200

    assert client.get("/api/state").status_code == 401
