import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .config import settings
from .db import AdminUser, SessionLocal, get_db

COOKIE = "kv_admin"
COOKIE_MAX_AGE = 60 * 60 * 24 * 7
PBKDF2_ROUNDS = 210_000
USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,32}$")
ROLES = ("admin", "operator")


def signing_key() -> bytes:
    raw = settings.secret_key or settings.admin_token or settings.admin_password or "kingvcam-admin"
    return hashlib.sha256(raw.encode("utf-8")).digest()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2${PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds, salt_hex, digest_hex = stored.split("$", 3)
        if algo != "pbkdf2":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(rounds),
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def normalize_username(raw: str) -> str:
    return raw.strip().lower()


def validate_username(raw: str) -> str:
    username = normalize_username(raw)
    if not USERNAME_RE.fullmatch(username):
        raise HTTPException(400, "usuario invalido")
    return username


def validate_password(raw: str) -> str:
    if len(raw) < 8:
        raise HTTPException(400, "senha deve ter ao menos 8 caracteres")
    return raw


def make_session(user_id: int) -> str:
    exp = int((datetime.now(timezone.utc) + timedelta(seconds=COOKIE_MAX_AGE)).timestamp())
    payload = f"{user_id}:{exp}"
    mac = hmac.new(signing_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{user_id}.{exp}.{mac}"


def parse_session(value: str) -> int | None:
    try:
        user_id_s, exp_s, mac = value.split(".", 2)
        payload = f"{user_id_s}:{exp_s}"
        expected = hmac.new(signing_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected):
            return None
        if int(exp_s) < int(datetime.now(timezone.utc).timestamp()):
            return None
        return int(user_id_s)
    except (ValueError, TypeError):
        return None


def bootstrap_admin() -> None:
    password = settings.admin_password or settings.admin_token
    if not password:
        return
    username = normalize_username(settings.admin_user or "admin")
    if not USERNAME_RE.fullmatch(username):
        username = "admin"
    db = SessionLocal()
    try:
        user = db.query(AdminUser).filter(AdminUser.username == username).one_or_none()
        if user is None:
            db.add(
                AdminUser(
                    username=username,
                    password_hash=hash_password(password),
                    role="admin",
                    is_active=True,
                )
            )
        else:
            user.password_hash = hash_password(password)
            user.role = "admin"
            user.is_active = True
        db.commit()
    finally:
        db.close()


def current_user(request: Request, db: Session = Depends(get_db)) -> AdminUser:
    is_api = request.url.path.startswith("/api/")
    token = request.headers.get("x-admin-token", "")
    if settings.admin_token and token and hmac.compare_digest(token, settings.admin_token):
        user = (
            db.query(AdminUser)
            .filter(AdminUser.role == "admin", AdminUser.is_active.is_(True))
            .order_by(AdminUser.id.asc())
            .first()
        )
        if user is not None:
            return user
    cookie = request.cookies.get(COOKIE, "")
    user_id = parse_session(cookie) if cookie else None
    user = db.get(AdminUser, user_id) if user_id else None
    if user is not None and user.is_active:
        return user
    if is_api:
        raise HTTPException(401, "nao autenticado")
    raise HTTPException(status_code=307, headers={"Location": "/admin/login"})


def require_admin_role(user: AdminUser = Depends(current_user)) -> AdminUser:
    if user.role != "admin":
        raise HTTPException(status_code=307, headers={"Location": "/admin?ok=forbidden"})
    return user


def count_active_admins(db: Session, exclude_id: int | None = None) -> int:
    query = db.query(AdminUser).filter(AdminUser.role == "admin", AdminUser.is_active.is_(True))
    if exclude_id is not None:
        query = query.filter(AdminUser.id != exclude_id)
    return query.count()
