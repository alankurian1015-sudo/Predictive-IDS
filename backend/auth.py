"""backend/auth.py: Authentication, JWT sessions, and RBAC middleware for PIDS."""
import datetime as dt
import os
import secrets
from typing import Any, Dict, List, Optional

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response, WebSocket, status
from pydantic import BaseModel, Field

from backend import db

# JWT Configuration
JWT_SECRET = os.getenv("PIDS_JWT_SECRET")
SECRET_FILE = db.DATA_DIR / ".jwt_secret"
if not JWT_SECRET:
    if SECRET_FILE.exists():
        JWT_SECRET = SECRET_FILE.read_text(encoding="utf-8").strip()
    else:
        JWT_SECRET = secrets.token_hex(32)  # 64 chars = 256 bits secure HMAC key
        db.DATA_DIR.mkdir(parents=True, exist_ok=True)
        SECRET_FILE.write_text(JWT_SECRET, encoding="utf-8")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 12
COOKIE_NAME = "pids_token"

router = APIRouter(prefix="/api/auth", tags=["auth"])


# ---------- Cryptographic Helpers ----------
def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt with salt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[dt.timedelta] = None) -> str:
    """Create signed JWT access token."""
    to_encode = data.copy()
    expire = dt.datetime.now(dt.timezone.utc) + (
        expires_delta or dt.timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    )
    to_encode.update({"exp": expire, "iat": dt.datetime.now(dt.timezone.utc)})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a JWT access token."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except (jwt.PyJWTError, Exception):
        return None


# ---------- Request Token Extraction & RBAC Dependencies ----------
def get_token_from_request(request: Request) -> Optional[str]:
    """Extract token from HttpOnly cookie first, then fallback to Authorization header."""
    cookie_token = request.cookies.get(COOKIE_NAME)
    if cookie_token:
        return cookie_token

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    return None


async def get_current_user(request: Request) -> Dict[str, Any]:
    """Dependency: Require an active authenticated user session."""
    token = get_token_from_request(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = payload["sub"]
    user = db.get_user_by_username(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account no longer active.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Sanitize user dictionary (strip hashed_password)
    user_data = dict(user)
    user_data.pop("hashed_password", None)
    return user_data


async def get_optional_user(request: Request) -> Optional[Dict[str, Any]]:
    """Dependency: Return user if authenticated, else None without raising 401."""
    try:
        return await get_current_user(request)
    except HTTPException:
        return None


def require_role(allowed_roles: List[str]):
    """Dependency Factory: Enforce Role-Based Access Control (RBAC)."""
    async def role_checker(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_role = current_user.get("role", "")
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Role '{user_role}' does not have sufficient permissions. Required: {', '.join(allowed_roles)}.",
            )
        return current_user
    return role_checker


async def authenticate_websocket(websocket: WebSocket) -> Optional[Dict[str, Any]]:
    """Verify WebSocket handshake via cookie or query param."""
    token = websocket.cookies.get(COOKIE_NAME) or websocket.query_params.get("token")
    if not token:
        return None
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        return None
    user = db.get_user_by_username(payload["sub"])
    if not user:
        return None
    user_data = dict(user)
    user_data.pop("hashed_password", None)
    return user_data


# ---------- Pydantic Request Models ----------
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=100)


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=30)
    password: str = Field(..., min_length=6, max_length=100)
    role: str = Field(..., pattern="^(admin|analyst|viewer)$")
    full_name: str = Field(..., min_length=1, max_length=100)


# ---------- Auth API Endpoints ----------
@router.post("/login")
def login(creds: LoginRequest, response: Response):
    """Authenticate user with username and password, return profile and set HttpOnly cookie."""
    user = db.get_user_by_username(creds.username)
    if not user or not verify_password(creds.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    # Update last login
    db.update_last_login(user["id"])

    # Create token
    token = create_access_token({
        "sub": user["username"],
        "role": user["role"],
        "name": user["full_name"],
    })

    # Set secure HttpOnly cookie
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_HOURS * 3600,
        samesite="lax",
        secure=False,  # Set to True in HTTPS production
        path="/",
    )

    return {
        "ok": True,
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "full_name": user["full_name"],
        },
    }


@router.post("/logout")
def logout(response: Response):
    """Clear session cookie."""
    response.delete_cookie(key=COOKIE_NAME, path="/")
    return {"ok": True, "message": "Successfully logged out."}


@router.get("/me")
def me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Return profile of currently logged-in user."""
    return {"ok": True, "user": current_user}


@router.get("/users")
def get_users(admin: Dict[str, Any] = Depends(require_role(["admin"]))):
    """List all user accounts (Admin only)."""
    return {"ok": True, "users": db.list_users()}


@router.post("/users")
def add_user(req: CreateUserRequest, admin: Dict[str, Any] = Depends(require_role(["admin"]))):
    """Create a new user account (Admin only)."""
    existing = db.get_user_by_username(req.username)
    if existing:
        raise HTTPException(status_code=400, detail=f"Username '{req.username}' already exists.")

    hashed = hash_password(req.password)
    user_id = db.create_user(req.username, hashed, req.role, req.full_name)
    return {"ok": True, "user_id": user_id, "username": req.username, "role": req.role}


@router.delete("/users/{user_id}")
def remove_user(user_id: int, admin: Dict[str, Any] = Depends(require_role(["admin"]))):
    """Deactivate a user account (Admin only)."""
    if admin["id"] == user_id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own admin account.")

    ok = db.delete_user(user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"ok": True, "message": f"User {user_id} deactivated."}
