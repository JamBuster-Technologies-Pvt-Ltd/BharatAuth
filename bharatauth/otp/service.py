# bharatauth/otp/service.py
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from bharatauth.config import get_config
from bharatauth.email import EmailService
from bharatauth.exceptions import AccountSuspendedError, UnauthorizedError
from bharatauth.login.service import (
    _get_account,
    _get_display_name,
    _get_email,
    _get_user_id,
    _is_known_device,
    _resolve_user,
)
from bharatauth.models import BAOTPToken, BASession, TokenPurpose
from bharatauth.tokens import TokenService

logger = logging.getLogger("bharatauth.otp")

_ENUMERATION_SAFE_RESPONSE = {
    "success": True,
    "message": "If that account exists, a code has been sent.",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def request_otp(
    db: Session,
    *,
    identifier: str,
    device_fingerprint: str | None = None,
) -> dict:
    """
    Send a 6-digit OTP code to the account's email.

    Enumeration-safe: always returns the same response whether or not
    the identifier resolves to a real account. An attacker cannot use
    this endpoint to enumerate valid email addresses or usernames.
    """
    identifier = (identifier or "").strip()
    user = _resolve_user(db, identifier)

    if user:
        account = _get_account(user)

        if not account.is_active:
            logger.info(
                f"BharatAuth: OTP for suspended account (no-op, enumeration-safe): "
                f"identifier={identifier}"
            )
            return _ENUMERATION_SAFE_RESPONSE

        # Invalidate any prior unused OTP tokens for this user
        user_id = _get_user_id(user)
        db.query(BAOTPToken).filter(
            BAOTPToken.user_id == user_id,
            BAOTPToken.purpose == TokenPurpose.EMAIL_LOGIN_OTP,
            BAOTPToken.used_at.is_(None),
        ).update({"used_at": _now()}, synchronize_session=False)

        otp_code = TokenService.generate_otp()

        token_record = BAOTPToken(
            user_id=user_id,
            token_hash=TokenService.hash_token(otp_code),
            purpose=TokenPurpose.EMAIL_LOGIN_OTP,
            device_fingerprint=device_fingerprint,
            expires_at=TokenService.otp_expiry(),
        )
        db.add(token_record)
        db.commit()

        # Send email — non-fatal if it fails (enumeration-safe response still returned)
        EmailService.send_otp(
            to=_get_email(user),
            otp_code=otp_code,
            display_name=_get_display_name(user),
        )

    else:
        logger.info(
            f"BharatAuth: OTP for unknown identifier (no-op, enumeration-safe): "
            f"identifier={identifier}"
        )

    return _ENUMERATION_SAFE_RESPONSE


def verify_otp(
    db: Session,
    *,
    identifier: str,
    otp_code: str,
    device_fingerprint: str | None = None,
    device_info: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> dict:
    """
    Verify a 6-digit OTP code and create a session.

    Device fingerprint is checked against the fingerprint stored at
    request time. A mismatch creates the session but sets
    is_verified_device=False — client should trigger step-up.

    Returns same shape as login():
        { access_token, refresh_token, token_type,
          is_verified_device, is_public_device, user }

    Raises:
        UnauthorizedError     — invalid/expired code
        AccountSuspendedError — account suspended
    """
    identifier = (identifier or "").strip()
    user = _resolve_user(db, identifier)

    if not user:
        raise UnauthorizedError("Invalid or expired code.")

    account = _get_account(user)
    if not account.is_active:
        raise AccountSuspendedError()

    user_id = _get_user_id(user)
    code_hash = TokenService.hash_token(otp_code)

    token_record = db.query(BAOTPToken).filter(
        BAOTPToken.user_id == user_id,
        BAOTPToken.token_hash == code_hash,
        BAOTPToken.purpose == TokenPurpose.EMAIL_LOGIN_OTP,
        BAOTPToken.used_at.is_(None),
    ).first()

    if not token_record:
        raise UnauthorizedError("Invalid or expired code.")

    if token_record.is_expired():
        raise UnauthorizedError("Invalid or expired code.")

    # ── Device fingerprint verification ───────────────────────────────
    fp_match = (
        token_record.device_fingerprint is None
        or token_record.device_fingerprint == device_fingerprint
    )
    # Known device = previously seen fingerprint OR fingerprint matches OTP request
    known_device = _is_known_device(db, user_id, device_fingerprint) or fp_match
    is_verified = known_device

    # ── Mark token consumed (before session creation — prevents races) ─
    token_record.used_at = _now()
    db.flush()

    # ── Create session ─────────────────────────────────────────────────
    token_pair = TokenService.create_token_pair(user_id)
    refresh_hash = TokenService.hash_token(token_pair["refresh_token"])

    # OTP login on own device = standard 30-day TTL
    expires_at = (
        TokenService.refresh_expiry_new_device()
        if not known_device
        else TokenService.refresh_expiry_standard()
    )

    session = BASession(
        user_id=user_id,
        refresh_token_hash=refresh_hash,
        access_jti=token_pair["access_jti"],
        device_fingerprint=device_fingerprint,
        device_info=device_info,
        ip_address=ip_address,
        user_agent=user_agent,
        is_public_device=False,
        is_verified_device=is_verified,
        expires_at=expires_at,
    )
    db.add(session)
    db.commit()

    logger.info(
        f"BharatAuth: OTP verify success — user_id={user_id} "
        f"fp_match={fp_match} is_verified={is_verified}"
    )

    return {
        "access_token": token_pair["access_token"],
        "refresh_token": token_pair["refresh_token"],
        "token_type": "bearer",
        "is_verified_device": is_verified,
        "is_public_device": False,
        "user": {"id": user_id, "email": _get_email(user)},
    }
