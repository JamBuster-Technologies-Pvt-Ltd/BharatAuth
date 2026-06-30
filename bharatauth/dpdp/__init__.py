# bharatauth/dpdp/__init__.py
"""
DPDP Act 2023 compliance layer.

  from bharatauth.dpdp import (
      record_consent,
      get_consents,
      withdraw_consent,
      export_user_data,
      validate_registration_consent,
  )

DESIGN PRINCIPLES:
  - Consent records are IMMUTABLE. No update or delete endpoints exist.
  - New rows only — the full audit trail is always preserved.
  - notice_version ties each consent to the exact privacy notice shown.
  - Six default categories (configurable via BharatAuthConfig.dpdp_categories).
  - All six must be granted for registration (validate_registration_consent).
  - Withdrawal appends a new row with granted=False — as easy as granting (DPDP §6).
"""

from bharatauth.dpdp.service import (
    record_consent,
    record_bulk_consent,
    get_consents,
    withdraw_consent,
    export_user_data,
    validate_registration_consent,
)

__all__ = [
    "record_consent",
    "record_bulk_consent",
    "get_consents",
    "withdraw_consent",
    "export_user_data",
    "validate_registration_consent",
]
