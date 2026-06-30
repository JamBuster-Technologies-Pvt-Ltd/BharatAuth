# bharatauth/pin/service.py
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from passlib.context import CryptContext
from sqlalchemy.orm import Session

from bharatauth.exceptions import (
    AccountSuspendedError,
    BadRequestError,
    NotFoundError,
    UnauthorizedError,
)
from bharatauth.login.service import _get_account, _get_email, _get_display_name, _resolve_user, _get_user_id
from bharatauth.models import BAOTPToken, TokenPurpose
from bharatauth.security.lockout import (
    check_account_lockout,
    clear_account_failures,
    record_account_failure,
)
from bharatauth.tokens import TokenService
from bharatauth.email import EmailService

logger = logging.getLogger("bharatauth.pin")
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

_PIN_RESET_TTL_MINUTES = 30


def _now() -> datetime:
    return datetime.now(timezone.utc)


def set_pin(db: Session, *, user: object, pin: str) -> dict:
    """
    Set or change a user's PIN.
    PIN must be 4–8 digits.

    Args:
        user: The authenticated user object (from your session).
        pin:  The raw PIN (4–8 numeric digits).
    """
    if not pin or not pin.isdigit() or not (4 <= len(pin) <= 8):
        raise BadRequestError("PIN must be 4–8 numeric digits.")

    account = _get_account(user)
    account.pin_hash = _pwd_context.hash(pin)
    db.commit()

    logger.info(f"BharatAuth: PIN set for user_id={_get_user_id(user)}")
    return {"success": True, "message": "PIN updated."}


def verify_pin(db: Session, *, user: object, pin: str) -> dict:
    """
    Verify the user's PIN (app-lock screen).

    Security: raises UnauthorizedError (401) on BOTH wrong PIN and lockout.
    This prevents an attacker with a stolen JWT from knowing if lockout fired.

    Args:
        user: The authenticated user object.
        pin:  The raw PIN entered by the user.
    """
    account = _get_account(user)

    if not account.is_active:
        raise AccountSuspendedError()

    # Lockout check — passes for_pin=True so it raises 401, not 423
    check_account_lockout(account, for_pin=True)

    if not account.pin_hash:
        raise BadRequestError("No PIN is set for this account.")

    if not _pwd_context.verify(pin, account.pin_hash):
        record_account_failure(account, db)
        # Always raise 401 — never signal lockout for PIN
        raise UnauthorizedError("Invalid PIN.")

    clear_account_failures(account, db)
    logger.info(f"BharatAuth: PIN verified for user_id={_get_user_id(user)}")
    return {"success": True}


def reset_pin_request(db: Session, *, identifier: str) -> dict:
    """
    Request a PIN reset email.
    Enumeration-safe: returns identical response for valid and invalid identifiers.
    """
    _SAFE_RESPONSE = {
        "success": True,
        "message": "If that account exists, a PIN reset link has been sent.",
    }

    identifier = (identifier or "").strip()
    user = _resolve_user(db, identifier)

    if not user:
        return _SAFE_RESPONSE

    account = _get_account(user)
    if not account.is_active:
        return _SAFE_RESPONSE

    user_id = _get_user_id(user)

    # Invalidate prior PIN reset tokens
    db.query(BAOTPToken).filter(
        BAOTPToken.user_id == user_id,
        BAOTPToken.purpose == TokenPurpose.PIN_RESET,
        BAOTPToken.used_at.is_(None),
    ).update({"used_at": _now()}, synchronize_session=False)

    raw_token = TokenService.generate_verification_token()
    token_record = BAOTPToken(
        user_id=user_id,
        token_hash=TokenService.hash_token(raw_token),
        purpose=TokenPurpose.PIN_RESET,
        expires_at=_now() + timedelta(minutes=_PIN_RESET_TTL_MINUTES),
    )
    db.add(token_record)
    db.commit()

    # Adopter must provide the full URL — BharatAuth provides the token
    token_url = f"pin-reset?token={raw_token}"  # Replace with your URL builder

    try:
        EmailService.send_pin_reset(
            to=_get_email(user),
            token_url=token_url,
            display_name=_get_display_name(user),
        )
    except Exception:
        pass  # Non-fatal, enumeration-safe

    return _SAFE_RESPONSE


def reset_pin_confirm(db: Session, *, token: str, new_pin: str) -> dict:
    """
    Confirm a PIN reset with the token from the email.

    Args:
        token:   The raw token from the reset URL.
        new_pin: The new PIN (4–8 digits).
    """
    if not new_pin or not new_pin.isdigit() or not (4 <= len(new_pin) <= 8):
        raise BadRequestError("PIN must be 4–8 numeric digits.")

    token_hash = TokenService.hash_token(token)
    record = db.query(BAOTPToken).filter(
        BAOTPToken.token_hash == token_hash,
        BAOTPToken.purpose == TokenPurpose.PIN_RESET,
        BAOTPToken.used_at.is_(None),
    ).first()

    if not record or record.is_expired():
        raise UnauthorizedError("Invalid or expired PIN reset token.")

    # Mark consumed
    record.used_at = _now()
    db.flush()

    # Update PIN — resolve account by user_id
    from bharatauth.models import BAAccount
    account = db.query(BAAccount).filter(
        BAAccount.username == f"__ext_{record.user_id}"
    ).first()

    if not account:
        # Managed mode: look up by user_id
        from bharatauth.models import BAUser
        user = db.query(BAUser).filter(BAUser.id == int(record.user_id)).first()
        if not user:
            raise NotFoundError("User not found.")
        account = user.account

    account.pin_hash = _pwd_context.hash(new_pin)
    db.commit()

    logger.info(f"BharatAuth: PIN reset confirmed for user_id={record.user_id}")
    return {"success": True, "message": "PIN has been reset."}
