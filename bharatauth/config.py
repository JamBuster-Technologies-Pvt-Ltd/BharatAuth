# bharatauth/config.py
"""
BharatAuth configuration — the single object that wires the SDK to your app.

TWO MODES
─────────
  managed   BharatAuth owns ba_users + ba_accounts. Zero-config for new projects.
            Run `alembic upgrade head` and you're done.

  external  You already have a User model. Pass callables — BharatAuth never
            touches your user table. ba_sessions, ba_consent_log, ba_otp_tokens
            key off an opaque user_id string.

USAGE
─────
  # Earliest possible point in your app startup (before routes are loaded):

  from bharatauth import configure

  # Managed mode (new project, no existing user table):
  configure(
      mode="managed",
      secret_key="change-me-in-production",
      database_url="postgresql://user:pass@localhost/mydb",
  )

  # External mode (existing User model):
  configure(
      mode="external",
      secret_key="change-me-in-production",
      database_url="postgresql://user:pass@localhost/mydb",
      get_user_by_email=lambda db, email: db.query(MyUser).filter_by(email=email).first(),
      get_user_by_username=lambda db, u: db.query(MyUser).filter_by(username=u).first(),
      get_user_id=lambda user: str(user.id),
      get_user_email=lambda user: user.email,
      get_user_display_name=lambda user: user.first_name,  # optional
  )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Optional


@dataclass
class BharatAuthConfig:
    # ── Mode ──────────────────────────────────────────────────────────
    mode: Literal["managed", "external"] = "managed"

    # ── Core secrets ──────────────────────────────────────────────────
    secret_key: str = ""
    algorithm: str = "HS256"

    # ── Database ──────────────────────────────────────────────────────
    database_url: str = ""

    # ── Token TTLs ────────────────────────────────────────────────────
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30
    new_device_token_expire_days: int = 7
    public_device_token_expire_hours: int = 2
    otp_expire_minutes: int = 10

    # ── Email (SMTP) ──────────────────────────────────────────────────
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "noreply@bharatauth.dev"
    smtp_tls: bool = True

    # ── Redis (optional — rate limiting degrades gracefully without) ──
    redis_url: Optional[str] = None

    # ── JWT issuer/audience (customise for your app) ──────────────────
    jwt_issuer: str = "bharatauth"
    jwt_audience: str = "bharatauth-client"

    # ── DPDP ──────────────────────────────────────────────────────────
    dpdp_notice_version: str = "1.0.0"
    dpdp_categories: list[str] = field(default_factory=lambda: [
        "identity", "contact", "location",
        "security", "communications", "analytics",
    ])

    # ── External-mode user resolver callables ─────────────────────────
    # Required when mode="external". Ignored in managed mode.
    get_user_by_email: Optional[Callable[[Any, str], Any]] = None
    get_user_by_username: Optional[Callable[[Any, str], Any]] = None
    get_user_id: Optional[Callable[[Any], str]] = None
    get_user_email: Optional[Callable[[Any], str]] = None
    get_user_display_name: Optional[Callable[[Any], str]] = None  # for email templates

    # ── DB session factory ─────────────────────────────────────────────
    # If not provided, BharatAuth creates its own from database_url.
    db_session_factory: Optional[Callable[[], Any]] = None

    def validate(self) -> None:
        if not self.secret_key:
            raise ValueError("BharatAuth: secret_key is required.")
        if not self.database_url and self.db_session_factory is None:
            raise ValueError(
                "BharatAuth: provide either database_url or db_session_factory."
            )
        if self.mode == "external":
            missing = [
                name for name, val in [
                    ("get_user_by_email", self.get_user_by_email),
                    ("get_user_by_username", self.get_user_by_username),
                    ("get_user_id", self.get_user_id),
                    ("get_user_email", self.get_user_email),
                ]
                if val is None
            ]
            if missing:
                raise ValueError(
                    f"BharatAuth external mode requires: {', '.join(missing)}"
                )


# ── Global singleton ──────────────────────────────────────────────────
_config: Optional[BharatAuthConfig] = None


def configure(**kwargs: Any) -> BharatAuthConfig:
    """
    Initialise BharatAuth. Call once at app startup before importing
    any bharatauth service functions.

    Returns the config object (useful for testing / inspection).
    """
    global _config
    _config = BharatAuthConfig(**kwargs)
    _config.validate()

    # Trigger DB engine + session factory setup
    from bharatauth.db import init_db
    init_db(_config)

    return _config


def get_config() -> BharatAuthConfig:
    """Return the active config. Raises if configure() was never called."""
    if _config is None:
        raise RuntimeError(
            "BharatAuth is not configured. Call bharatauth.configure() "
            "at application startup before using any auth functions."
        )
    return _config
