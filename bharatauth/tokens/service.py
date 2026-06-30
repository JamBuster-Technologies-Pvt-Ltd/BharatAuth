# bharatauth/tokens/service.py
from __future__ import annotations

import hashlib
import random
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple

from jose import JWTError, jwt

from bharatauth.config import get_config
from bharatauth.exceptions import InvalidTokenError, TokenExpiredError


def _now() -> datetime:
    return datetime.now(timezone.utc)


class TokenService:
    """
    Single source of truth for all token operations.

    Security principles:
    - Raw tokens are NEVER stored in the database.
    - All stored tokens are SHA-256 hashes of the raw value.
    - Access tokens are short-lived JWTs (default 15 min).
    - Refresh tokens are opaque 64-byte URL-safe strings.
    - OTP codes are 6-digit numeric strings.
    - Verification tokens (email, password reset) are 48-byte opaque strings.
    """

    # ── Hashing ───────────────────────────────────────────────────────

    @staticmethod
    def hash_token(token: str) -> str:
        """SHA-256 hash of any token. Store this; never store the raw value."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    # ── OTP ───────────────────────────────────────────────────────────

    @staticmethod
    def generate_otp() -> str:
        """
        Generate a 6-digit numeric OTP using secrets module.
        secrets.randbelow is cryptographically secure — do not use random.randint.
        """
        return f"{secrets.randbelow(1_000_000):06d}"

    # ── Opaque tokens ─────────────────────────────────────────────────

    @staticmethod
    def generate_refresh_token() -> str:
        """64-byte URL-safe opaque string for refresh tokens."""
        return secrets.token_urlsafe(64)

    @staticmethod
    def generate_verification_token() -> str:
        """48-byte URL-safe opaque string for email verify / password reset."""
        return secrets.token_urlsafe(48)

    # ── JWT ───────────────────────────────────────────────────────────

    @staticmethod
    def create_access_token(user_id: str) -> Tuple[str, str]:
        """
        Mint a JWT access token.
        Returns (token, jti) — jti is stored in ba_sessions for revocation.
        """
        cfg = get_config()
        now = _now()
        expire = now + timedelta(minutes=cfg.access_token_expire_minutes)
        jti = str(uuid.uuid4())

        payload = {
            "sub": str(user_id),
            "jti": jti,
            "type": "access",
            "iss": cfg.jwt_issuer,
            "aud": cfg.jwt_audience,
            "iat": now,
            "nbf": now,
            "exp": expire,
        }

        token = jwt.encode(payload, cfg.secret_key, algorithm=cfg.algorithm)
        return token, jti

    @staticmethod
    def decode_access_token(token: str) -> dict:
        """
        Decode and validate a JWT access token.
        Raises InvalidTokenError or TokenExpiredError on failure.
        """
        cfg = get_config()
        try:
            payload = jwt.decode(
                token,
                cfg.secret_key,
                algorithms=[cfg.algorithm],
                audience=cfg.jwt_audience,
                issuer=cfg.jwt_issuer,
            )
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError()
        except JWTError:
            raise InvalidTokenError()

        if payload.get("type") != "access":
            raise InvalidTokenError("Token is not an access token.")

        return payload

    # ── Token pair (access + refresh) ────────────────────────────────

    @staticmethod
    def create_token_pair(user_id: str) -> Dict[str, str]:
        """
        Create a full access + refresh token pair.
        Returns dict with: access_token, access_jti, refresh_token, token_type.
        """
        access_token, access_jti = TokenService.create_access_token(user_id)
        refresh_token = TokenService.generate_refresh_token()

        return {
            "access_token": access_token,
            "access_jti": access_jti,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    # ── Expiry helpers ────────────────────────────────────────────────

    @staticmethod
    def refresh_expiry_standard() -> datetime:
        cfg = get_config()
        return _now() + timedelta(days=cfg.refresh_token_expire_days)

    @staticmethod
    def refresh_expiry_new_device() -> datetime:
        cfg = get_config()
        return _now() + timedelta(days=cfg.new_device_token_expire_days)

    @staticmethod
    def refresh_expiry_public_device() -> datetime:
        cfg = get_config()
        return _now() + timedelta(hours=cfg.public_device_token_expire_hours)

    @staticmethod
    def otp_expiry() -> datetime:
        cfg = get_config()
        return _now() + timedelta(minutes=cfg.otp_expire_minutes)
