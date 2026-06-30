# bharatauth/login/service.py
"""
Login service — password verification, device trust, session creation.

FLOW:
  1. IP block check
  2. Resolve user (managed: BAAccount query | external: adopter callable)
  3. Account active check
  4. Lockout check
  5. bcrypt password verify
  6. Record success / failure
  7. Device trust detection
  8. Session creation with TTL based on trust level
  9. Return token pair + trust metadata
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from passlib.context import CryptContext
from sqlalchemy.orm import Session

from bharatauth.config import get_config
from bharatauth.email import EmailService
from bharatauth.exceptions import (
    AccountSuspendedError,
    ForbiddenError,
    NotFoundError,
    UnauthorizedError,
)
from bharatauth.models import BASession
from bharatauth.security.lockout import (
    check_account_lockout,
    check_ip_blocked,
    clear_account_failures,
    record_account_failure,
    record_ip_failure,
)
from bharatauth.tokens import TokenService

logger = logging.getLogger("bharatauth.login")
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _verify_password(plain: str, hashed: str) -> bool:
    return _pwd_context.verify(plain, hashed)


def hash_password(plain: str) -> str:
    """Hash a password for storage. Use this at registration."""
    return _pwd_context.hash(plain)


def _resolve_user(db: Session, identifier: str) -> Any | None:
    """
    Find a user by email or username.
    Managed mode: queries BAAccount directly.
    External mode: uses adopter-supplied callables.
    """
    cfg = get_config()

    if cfg.mode == "managed":
        from bharatauth.models import BAAccount
        user = db.query(BAAccount).filter(BAAccount.email == identifier).first()
        if not user:
            user = db.query(BAAccount).filter(BAAccount.username == identifier).first()
        return user  # returns BAAccount in managed mode

    # External mode
    user = cfg.get_user_by_email(db, identifier)
    if not user:
        user = cfg.get_user_by_username(db, identifier)
    return user


def _get_user_id(user: Any) -> str:
    cfg = get_config()
    if cfg.mode == "managed":
        # In managed mode, user is BAAccount — use user_id
        return str(user.user_id)
    return str(cfg.get_user_id(user))


def _get_email(user: Any) -> str:
    cfg = get_config()
    if cfg.mode == "managed":
        return user.email
    return cfg.get_user_email(user)


def _get_display_name(user: Any) -> str:
    cfg = get_config()
    if cfg.mode == "managed":
        return ""  # managed mode has no name (minimal ba_users)
    fn = cfg.get_user_display_name
    return fn(user) if fn else ""


def _get_account(user: Any) -> Any:
    """In managed mode, user IS the account. In external mode, return user for duck-typing."""
    cfg = get_config()
    if cfg.mode == "managed":
        return user  # BAAccount
    # External mode: adopter's user object must have lockout attributes
    # OR we use a BharatAuth-owned lockout record keyed by user_id
    return _get_or_create_lockout_record(user)


def _get_or_create_lockout_record(user: Any):
    """
    External mode: fetch or create a BAAccount-like lockout record
    keyed to the external user_id. BharatAuth stores lockout state
    in its own ba_accounts table without touching the adopter's table.
    """
    from bharatauth.db import get_db
    from bharatauth.models import BAAccount

    user_id = str(get_config().get_user_id(user))

    with get_db() as db:
        record = db.query(BAAccount).filter(
            BAAccount.username == f"__ext_{user_id}"
        ).first()

        if not record:
            record = BAAccount(
                user_id=0,  # sentinel for external mode
                email=f"__ext_{user_id}@bharatauth.internal",
                username=f"__ext_{user_id}",
                is_active=True,
                email_verified=True,
            )
            db.add(record)
            db.flush()

        return record


def _is_known_device(db: Session, user_id: str, device_fingerprint: str | None) -> bool:
    """Check if this device fingerprint has been seen before for this user."""
    if not device_fingerprint:
        return False
    return db.query(BASession).filter(
        BASession.user_id == user_id,
        BASession.device_fingerprint == device_fingerprint,
        BASession.revoked == False,
    ).first() is not None


def login(
    db: Session,
    *,
    identifier: str,
    password: str,
    device_fingerprint: str | None = None,
    is_public_device: bool = False,
    device_info: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> dict:
    """
    Authenticate a user with password.

    Returns:
        {
            access_token, refresh_token, token_type,
            is_verified_device, is_public_device,
            user: { id, email }
        }

    Raises:
        UnauthorizedError     — wrong credentials
        AccountSuspendedError — account inactive
        AccountLockedError    — brute-force lockout (423)
        IPBlockedError        — IP blocked (429)
    """
    identifier = (identifier or "").strip()

    # ── Step 1: IP block check ─────────────────────────────────────────
    check_ip_blocked(ip_address, db)

    # ── Step 2: Resolve user ───────────────────────────────────────────
    user = _resolve_user(db, identifier)

    if user is None:
        # Timing-safe: still do a dummy bcrypt to prevent timing attacks
        _pwd_context.dummy_verify()
        raise UnauthorizedError("Invalid credentials.")

    account = _get_account(user)
    user_id = _get_user_id(user)

    # ── Step 3: Active check ───────────────────────────────────────────
    if not account.is_active:
        raise AccountSuspendedError()

    # ── Step 4: Lockout check ──────────────────────────────────────────
    check_account_lockout(account)

    # ── Step 5: Password verify ────────────────────────────────────────
    if not account.password_hash or not _verify_password(password, account.password_hash):
        record_account_failure(account, db)
        record_ip_failure(ip_address, identifier, db)
        raise UnauthorizedError("Invalid credentials.")

    # ── Step 6: Clear failures ─────────────────────────────────────────
    clear_account_failures(account, db)

    # ── Step 7: Device trust ───────────────────────────────────────────
    known_device = _is_known_device(db, user_id, device_fingerprint)
    is_verified = known_device

    if not known_device and device_fingerprint:
        logger.info(f"BharatAuth: New device for user_id={user_id}")
        try:
            EmailService.send_new_device_alert(
                to=_get_email(user),
                device_info=device_info or "",
                display_name=_get_display_name(user),
            )
        except Exception:
            pass  # Non-fatal

    # ── Step 8: Create session ─────────────────────────────────────────
    token_pair = TokenService.create_token_pair(user_id)
    refresh_hash = TokenService.hash_token(token_pair["refresh_token"])

    if is_public_device:
        expires_at = TokenService.refresh_expiry_public_device()
    elif not known_device and device_fingerprint:
        expires_at = TokenService.refresh_expiry_new_device()
    else:
        expires_at = TokenService.refresh_expiry_standard()

    session = BASession(
        user_id=user_id,
        refresh_token_hash=refresh_hash,
        access_jti=token_pair["access_jti"],
        device_fingerprint=device_fingerprint,
        device_info=device_info,
        ip_address=ip_address,
        user_agent=user_agent,
        is_public_device=is_public_device,
        is_verified_device=is_verified,
        expires_at=expires_at,
    )
    db.add(session)
    db.commit()

    logger.info(
        f"BharatAuth: Login success — user_id={user_id} "
        f"public={is_public_device} verified={is_verified}"
    )

    return {
        "access_token": token_pair["access_token"],
        "refresh_token": token_pair["refresh_token"],
        "token_type": "bearer",
        "is_verified_device": is_verified,
        "is_public_device": is_public_device,
        "user": {"id": user_id, "email": _get_email(user)},
    }


def refresh_session(db: Session, *, refresh_token: str) -> dict:
    """
    Rotate a refresh token. Returns a new token pair.
    Old session is revoked; new session is created.
    """
    token_hash = TokenService.hash_token(refresh_token)
    session = db.query(BASession).filter(
        BASession.refresh_token_hash == token_hash,
        BASession.revoked == False,
    ).first()

    if not session or not session.is_valid():
        raise UnauthorizedError("Invalid or expired refresh token.")

    # Revoke old session
    session.revoked = True
    session.revoked_at = _now()

    # New token pair
    token_pair = TokenService.create_token_pair(session.user_id)
    refresh_hash = TokenService.hash_token(token_pair["refresh_token"])

    new_session = BASession(
        user_id=session.user_id,
        refresh_token_hash=refresh_hash,
        access_jti=token_pair["access_jti"],
        device_fingerprint=session.device_fingerprint,
        device_info=session.device_info,
        ip_address=session.ip_address,
        user_agent=session.user_agent,
        is_public_device=session.is_public_device,
        is_verified_device=session.is_verified_device,
        expires_at=session.expires_at,  # Preserve original expiry
    )
    db.add(new_session)
    db.commit()

    return {
        "access_token": token_pair["access_token"],
        "refresh_token": token_pair["refresh_token"],
        "token_type": "bearer",
    }


def logout(db: Session, *, refresh_token: str) -> dict:
    """Revoke a single session."""
    token_hash = TokenService.hash_token(refresh_token)
    session = db.query(BASession).filter(
        BASession.refresh_token_hash == token_hash,
    ).first()

    if session:
        session.revoked = True
        session.revoked_at = _now()
        db.commit()

    return {"success": True}


def logout_all(db: Session, *, user_id: str) -> dict:
    """Revoke all sessions for a user."""
    now = _now()
    db.query(BASession).filter(
        BASession.user_id == str(user_id),
        BASession.revoked == False,
    ).update({"revoked": True, "revoked_at": now}, synchronize_session=False)
    db.commit()
    return {"success": True, "message": "All sessions revoked."}


def list_sessions(db: Session, *, user_id: str) -> list[dict]:
    """Return all active sessions for a user."""
    sessions = db.query(BASession).filter(
        BASession.user_id == str(user_id),
        BASession.revoked == False,
    ).order_by(BASession.created_at.desc()).all()

    return [
        {
            "id": s.id,
            "device_info": s.device_info,
            "ip_address": s.ip_address,
            "is_public_device": s.is_public_device,
            "is_verified_device": s.is_verified_device,
            "created_at": s.created_at.isoformat(),
            "expires_at": s.expires_at.isoformat(),
            "last_used_at": s.last_used_at.isoformat() if s.last_used_at else None,
        }
        for s in sessions
        if not s.is_expired()
    ]


def get_current_user_id(token: str) -> str:
    """
    Decode a JWT access token and return the user_id.
    Raises InvalidTokenError / TokenExpiredError on failure.
    """
    payload = TokenService.decode_access_token(token)
    return str(payload["sub"])
