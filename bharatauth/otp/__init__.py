# bharatauth/otp/__init__.py
"""
Email OTP — passwordless login.

  from bharatauth.otp import request_otp, verify_otp

FLOW:
  1. POST /auth/otp/request  → sends 6-digit code to email
  2. POST /auth/otp/verify   → validates code, returns session

Enumeration-safe: both endpoints return identical responses
whether or not the identifier resolves to a real account.
"""

from bharatauth.otp.service import request_otp, verify_otp

__all__ = ["request_otp", "verify_otp"]
