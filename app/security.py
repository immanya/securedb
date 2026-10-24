from datetime import timedelta
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from . import audit
from .config import JWT_SECRET, ACCESS_TOKEN_MINUTES
from .db import get_db
from .models import User, now

ph = PasswordHasher()  # Argon2id by default
bearer = HTTPBearer(auto_error=False)

PERMISSIONS = {
    "admin":   {"view", "backup", "restore", "delete", "users", "logs", "databases"},
    "manager": {"view", "backup", "restore", "logs"},
    "viewer":  {"view"},
}


def hash_password(pw: str) -> str:
    return ph.hash(pw)


def check_password(hashed: str, pw: str) -> bool:
    try:
        return ph.verify(hashed, pw)
    except VerifyMismatchError:
        return False


def make_token(user: User) -> str:
    exp = now() + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    return jwt.encode({"sub": str(user.id), "role": user.role, "exp": exp}, JWT_SECRET, algorithm="HS256")


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def current_user(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(bearer),
                 db: Session = Depends(get_db)) -> User:
    if not creds:
        audit.log(db, "unknown", "api_access", "denied", client_ip(request), "missing token")
        raise HTTPException(401, "Not authenticated")
    try:
        data = jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        audit.log(db, "unknown", "api_access", "denied", client_ip(request), "invalid token")
        raise HTTPException(401, "Invalid or expired token")
    user = db.get(User, int(data["sub"]))
    if not user or user.status != "active":
        raise HTTPException(401, "Account disabled")
    return user  # role is read from the DB, never trusted from the token


def require_perm(perm: str):
    """Deny by default: the backend checks the role on every sensitive call."""
    def dep(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)) -> User:
        if perm not in PERMISSIONS.get(user.role, set()):
            audit.log(db, user.username, "unauthorized", "denied", client_ip(request),
                      f"{user.role} tried {request.method} {request.url.path}")
            audit.alert(db, "unauthorized_action", "medium",
                        f"{user.role} '{user.username}' attempted {request.method} {request.url.path}")
            raise HTTPException(403, "Insufficient permissions")
        return user
    return dep
