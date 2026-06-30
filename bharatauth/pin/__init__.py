# bharatauth/pin/__init__.py
"""
PIN app-lock — set, verify, and reset.

  from bharatauth.pin import set_pin, verify_pin, reset_pin

PIN is bcrypt-hashed at the same cost factor as passwords.
Shares the brute-force lockout counter with login — 5 wrong PINs
trigger the same soft lock.

SECURITY NOTE:
  verify_pin raises UnauthorizedError (401) on lockout — NOT 423.
  This is intentional: an attacker with a stolen JWT must not receive
  any signal that lockout has triggered. 401 is indistinguishable
  from wrong PIN.
"""

from bharatauth.pin.service import set_pin, verify_pin, reset_pin_request, reset_pin_confirm

__all__ = ["set_pin", "verify_pin", "reset_pin_request", "reset_pin_confirm"]
