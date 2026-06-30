# bharatauth/__init__.py
"""
BharatAuth — Production-grade auth SDK for Indian apps.

  pip install bharatauth

QUICK START
───────────
  from bharatauth import configure

  configure(
      secret_key="your-secret",
      database_url="postgresql://...",
  )

  # Then use domain modules:
  from bharatauth.login import login, refresh, logout
  from bharatauth.otp   import request_otp, verify_otp
  from bharatauth.pin   import set_pin, verify_pin
  from bharatauth.dpdp  import record_consent, get_consents, withdraw_consent

  # Or mount the pre-built FastAPI router:
  from bharatauth.fastapi_router import router as auth_router
  app.include_router(auth_router, prefix="/auth", tags=["Auth"])

MODULES
───────
  bharatauth.login    — password login, session refresh, logout
  bharatauth.otp      — email OTP request + verify (passwordless)
  bharatauth.pin      — PIN set / verify / reset (app-lock)
  bharatauth.email    — email sending (OTP, verification, alerts)
  bharatauth.dpdp     — DPDP consent capture, audit, withdrawal, export
  bharatauth.security — rate limiting, IP block, brute-force lockout
  bharatauth.tokens   — JWT + opaque token utilities
  bharatauth.sessions — session trust matrix, device fingerprinting
  bharatauth.models   — SQLAlchemy models (ba_ prefixed tables)
"""

__version__ = "0.1.0"
__author__ = "JamBuster Technologies Pvt Ltd"
__license__ = "MIT"

from bharatauth.config import configure, get_config

__all__ = [
    "configure",
    "get_config",
    "__version__",
]
