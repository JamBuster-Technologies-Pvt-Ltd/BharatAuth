# bharatauth/models/__init__.py
"""
BharatAuth SQLAlchemy models — all tables prefixed ba_

MANAGED MODE TABLES:
  ba_users        — minimal identity anchor (id + timestamps)
  ba_accounts     — credentials + lockout state

SHARED TABLES (both modes):
  ba_sessions     — session trust matrix, device fingerprinting
  ba_otp_tokens   — OTP + verification tokens (all purposes)
  ba_consent_log  — DPDP immutable audit trail
  ba_ip_blocks    — credential-stuffing IP blocks

Table prefix `ba_` ensures zero collision with adopter's schema.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger, Boolean, DateTime, Enum, ForeignKey,
    Index, Integer, String, Text, func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from bharatauth.db import BharatAuthBase


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ═══════════════════════════════════════════════════════════════
# MANAGED MODE — ba_users + ba_accounts
# (only created when mode="managed")
# ═══════════════════════════════════════════════════════════════

class BAUser(BharatAuthBase):
    """
    Minimal identity anchor. Owns nothing except an ID and timestamps.
    All auth state lives in BAAccount. All personal data lives in
    the adopter's own tables (or is intentionally omitted).
    """
    __tablename__ = "ba_users"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )

    # Relationships
    account: Mapped["BAAccount"] = relationship(
        "BAAccount", back_populates="user", uselist=False, cascade="all, delete-orphan"
    )
    sessions: Mapped[list["BASession"]] = relationship(
        "BASession", back_populates="user", cascade="all, delete-orphan"
    )
    otp_tokens: Mapped[list["BAOTPToken"]] = relationship(
        "BAOTPToken", back_populates="user", cascade="all, delete-orphan"
    )
    consent_logs: Mapped[list["BAConsentLog"]] = relationship(
        "BAConsentLog", back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<BAUser id={self.id}>"


class BAAccount(BharatAuthBase):
    """
    Credentials and lockout state for a BAUser.
    One-to-one with BAUser.
    """
    __tablename__ = "ba_accounts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("ba_users.id", ondelete="CASCADE"),
        nullable=False, unique=True,
    )

    # ── Credentials ───────────────────────────────────────────────────
    email: Mapped[str] = mapped_column(String(254), nullable=False, unique=True, index=True)
    username: Mapped[str | None] = mapped_column(String(50), nullable=True, unique=True, index=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    pin_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # ── Status flags ──────────────────────────────────────────────────
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # ── Brute-force lockout (DB-backed, Redis-independent) ────────────
    login_fail_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    lockout_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    # Relationship
    user: Mapped["BAUser"] = relationship("BAUser", back_populates="account")

    def __repr__(self) -> str:
        return f"<BAAccount email={self.email}>"


# ═══════════════════════════════════════════════════════════════
# SHARED — ba_sessions
# ═══════════════════════════════════════════════════════════════

class BASession(BharatAuthBase):
    """
    Session trust matrix. One row per active login.

    user_id is an opaque string in external mode (no FK constraint).
    In managed mode it references ba_users.id.

    Trust levels:
      own_known    — 30 day TTL, full access
      own_new      — 7 day TTL, sensitive routes blocked
      public       — 2 hour TTL, memory-only on client
    """
    __tablename__ = "ba_sessions"
    __table_args__ = (
        Index("ix_ba_sessions_user_id", "user_id"),
        Index("ix_ba_sessions_device_fingerprint", "device_fingerprint"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    # External mode: bare string (no FK). Managed mode: FK enforced via back_populates.
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # ── Token hashes (raw tokens never stored) ────────────────────────
    refresh_token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    access_jti: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    # ── Device context ────────────────────────────────────────────────
    device_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device_info: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Trust flags ───────────────────────────────────────────────────
    is_public_device: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_verified_device: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # ── Lifecycle ─────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Managed-mode relationship only (set up in managed init)
    user: Mapped["BAUser | None"] = relationship(
        "BAUser", back_populates="sessions",
        foreign_keys="[BASession.user_id]",
        primaryjoin="BASession.user_id == cast(BAUser.id, String)",
    )

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def is_valid(self) -> bool:
        return not self.revoked and not self.is_expired()


# ═══════════════════════════════════════════════════════════════
# SHARED — ba_otp_tokens
# ═══════════════════════════════════════════════════════════════

import enum

class TokenPurpose(str, enum.Enum):
    EMAIL_LOGIN_OTP   = "email_login_otp"
    EMAIL_VERIFY      = "email_verify"
    PASSWORD_RESET    = "password_reset"
    PIN_RESET         = "pin_reset"


class BAOTPToken(BharatAuthBase):
    """
    Single-use tokens for OTP login, email verification, password reset, PIN reset.
    Raw token is emailed to user; only SHA-256 hash is stored.
    """
    __tablename__ = "ba_otp_tokens"
    __table_args__ = (
        Index("ix_ba_otp_tokens_user_id", "user_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    purpose: Mapped[TokenPurpose] = mapped_column(
        Enum(TokenPurpose, name="ba_token_purpose"), nullable=False
    )
    device_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Managed-mode relationship
    user: Mapped["BAUser | None"] = relationship("BAUser", back_populates="otp_tokens")

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def is_used(self) -> bool:
        return self.used_at is not None


# ═══════════════════════════════════════════════════════════════
# SHARED — ba_consent_log  (DPDP immutable audit trail)
# ═══════════════════════════════════════════════════════════════

class ConsentCategory(str, enum.Enum):
    IDENTITY       = "identity"
    CONTACT        = "contact"
    LOCATION       = "location"
    SECURITY       = "security"
    COMMUNICATIONS = "communications"
    ANALYTICS      = "analytics"


class BAConsentLog(BharatAuthBase):
    """
    Immutable DPDP consent audit trail.

    NEVER updated or deleted — new rows only.
    Each row records a single consent decision at a point in time.
    The most recent row per category is the current state.

    Stores: who consented, to what, under which notice version,
    from which IP, at what time. Proves informed consent.
    """
    __tablename__ = "ba_consent_log"
    __table_args__ = (
        Index("ix_ba_consent_user_category", "user_id", "consent_category"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    consent_category: Mapped[str] = mapped_column(String(50), nullable=False)
    granted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    notice_version: Mapped[str] = mapped_column(String(20), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    # Managed-mode relationship
    user: Mapped["BAUser | None"] = relationship("BAUser", back_populates="consent_logs")


# ═══════════════════════════════════════════════════════════════
# SHARED — ba_ip_blocks
# ═══════════════════════════════════════════════════════════════

class BAIPBlock(BharatAuthBase):
    """
    DB-backed IP block for credential-stuffing protection.
    Triggered after 3+ distinct accounts fail from the same IP.
    Redis fast-path used when available; this is the fallback source of truth.
    """
    __tablename__ = "ba_ip_blocks"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, unique=True, index=True)
    blocked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    def is_active(self) -> bool:
        return datetime.now(timezone.utc) < self.expires_at


def register_models() -> None:
    """
    Import all models so BharatAuthBase.metadata is fully populated
    before create_all() is called. Called by init_db in managed mode.
    """
    # Models are defined in this file — imported by being in this module.
    pass
