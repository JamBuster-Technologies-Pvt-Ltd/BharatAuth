# BharatAuth

**Production-grade auth SDK for Indian apps.**

Email OTP · Password login · PIN app-lock · DPDP consent · Device trust matrix · Brute-force protection

Built from a real production auth system. Battle-tested on FastAPI + PostgreSQL.

---

## Install

```bash
pip install bharatauth
```

---

## Quick Start

### Managed mode (new project — no existing user table)

```python
from bharatauth import configure

configure(
    mode="managed",
    secret_key="change-me-in-production",
    database_url="postgresql://user:pass@localhost/mydb",
    smtp_host="smtp.yourprovider.com",
    smtp_user="noreply@yourapp.com",
    smtp_password="...",
)
```

BharatAuth creates `ba_users`, `ba_accounts`, `ba_sessions`, `ba_otp_tokens`, `ba_consent_log`, `ba_ip_blocks` and manages them entirely.

### External mode (you already have a User model)

```python
from bharatauth import configure

configure(
    mode="external",
    secret_key="change-me-in-production",
    database_url="postgresql://user:pass@localhost/mydb",
    get_user_by_email=lambda db, email: db.query(MyUser).filter_by(email=email).first(),
    get_user_by_username=lambda db, u: db.query(MyUser).filter_by(username=u).first(),
    get_user_id=lambda user: str(user.id),
    get_user_email=lambda user: user.email,
    get_user_display_name=lambda user: user.first_name,
)
```

BharatAuth stores sessions, OTP tokens, and DPDP consent logs in its own `ba_*` tables using your user's ID as an opaque string. Your user table is never touched.

---

## Drop-in FastAPI Router

```python
from fastapi import FastAPI
from bharatauth.fastapi_router import router as auth_router, bharatauth_exception_handler
from bharatauth.exceptions import BharatAuthError

app = FastAPI()
app.add_exception_handler(BharatAuthError, bharatauth_exception_handler)
app.include_router(auth_router, prefix="/auth", tags=["Auth"])
```

This mounts:

| Method | Path | Description |
|--------|------|-------------|
| POST | /auth/login | Password login |
| POST | /auth/otp/request | Send OTP email |
| POST | /auth/otp/verify | Verify OTP, create session |
| POST | /auth/pin/set | Set/change PIN |
| POST | /auth/pin/verify | Verify PIN (app-lock) |
| POST | /auth/pin/reset/request | PIN reset email |
| POST | /auth/pin/reset/confirm | Confirm PIN reset |
| POST | /auth/refresh | Rotate refresh token |
| POST | /auth/logout | Revoke session |
| POST | /auth/logout-all | Revoke all sessions |
| GET | /auth/sessions | List active sessions |
| GET | /auth/me | Current user from token |
| GET | /auth/privacy/consents | DPDP consent dashboard |
| POST | /auth/privacy/consent/withdraw | Withdraw consent category |
| GET | /auth/privacy/export | DPDP Right of Access export |

---

## Use Directly (without the router)

```python
from bharatauth.login import login, refresh_session, logout
from bharatauth.otp   import request_otp, verify_otp
from bharatauth.pin   import set_pin, verify_pin
from bharatauth.dpdp  import record_consent, get_consents, withdraw_consent, export_user_data

# Password login
result = login(db, identifier="user@example.com", password="secret",
               device_fingerprint="sha256...", is_public_device=False)

# Email OTP
request_otp(db, identifier="user@example.com", device_fingerprint="sha256...")
verify_otp(db, identifier="user@example.com", otp_code="483920", device_fingerprint="sha256...")

# PIN
set_pin(db, user=user_obj, pin="4829")
verify_pin(db, user=user_obj, pin="4829")

# DPDP — record consent at registration
from bharatauth.dpdp import validate_registration_consent, record_bulk_consent

consents = [
    {"category": "identity", "granted": True},
    {"category": "contact", "granted": True},
    {"category": "location", "granted": True},
    {"category": "security", "granted": True},
    {"category": "communications", "granted": True},
    {"category": "analytics", "granted": True},
]
validate_registration_consent(consents)  # raises ConsentRequiredError if any missing
record_bulk_consent(db, user_id=str(user.id), consents=consents, ip_address="...")
```

---

## Security Model

### Session Trust Matrix

| Scenario | TTL | Step-up Required |
|----------|-----|-----------------|
| Own device, known | 30 days | None |
| Own device, OTP login | 30 days | None |
| New unrecognised device | 7 days | Before sensitive actions |
| Public / borrowed device | 2 hours | Every sensitive action |

### Brute-Force Protection (two layers)

**Layer 1 — Route-level (Redis):** Per-IP request rate limits. Fails open if Redis is unavailable — auth correctness is maintained by Layer 2.

**Layer 2 — Service-level (PostgreSQL):** Per-account failure counting. Redis-independent.

| Tier | Trigger | Action |
|------|---------|--------|
| Soft lock | 5 failures | Locked 7 minutes (423) |
| Hard lock | 10 failures | Email verification required (423) |
| IP block | 3+ distinct accounts from same IP | IP blocked 24h (429) |

### PIN Security

PIN lockout returns **401**, not 423. An attacker with a stolen JWT receives no signal that lockout triggered — 401 is indistinguishable from wrong PIN.

---

## DPDP Compliance (India)

BharatAuth implements the Digital Personal Data Protection Act 2023:

- **Six consent categories:** identity, contact, location, security, communications, analytics
- **Immutable audit trail:** consent records are never updated or deleted — new rows only
- **Notice versioning:** each consent row records the exact privacy notice version shown
- **Right of withdrawal:** as easy as granting (single POST, DPDP §6)
- **Right of access:** `export_user_data()` returns all auth data BharatAuth holds
- **Configurable categories:** override via `BharatAuthConfig.dpdp_categories`

---

## Configuration Reference

```python
configure(
    # Required
    mode="managed",               # "managed" | "external"
    secret_key="...",             # JWT signing secret

    # Database (one of these is required)
    database_url="postgresql://...",
    db_session_factory=get_db,    # your own SQLAlchemy session factory

    # Token TTLs
    access_token_expire_minutes=15,
    refresh_token_expire_days=30,
    new_device_token_expire_days=7,
    public_device_token_expire_hours=2,
    otp_expire_minutes=10,

    # Email (SMTP)
    smtp_host="smtp.example.com",
    smtp_port=587,
    smtp_user="noreply@example.com",
    smtp_password="...",
    smtp_from="noreply@example.com",
    smtp_tls=True,

    # Redis (optional — rate limiting only, fails open without it)
    redis_url="redis://localhost:6379",

    # JWT claims
    jwt_issuer="your-app",
    jwt_audience="your-app-client",

    # DPDP
    dpdp_notice_version="1.0.0",
    dpdp_categories=["identity", "contact", "location",
                     "security", "communications", "analytics"],

    # External mode only
    get_user_by_email=...,
    get_user_by_username=...,
    get_user_id=...,
    get_user_email=...,
    get_user_display_name=...,    # optional, for email templates
)
```

---

## Custom Email Backend

Swap the SMTP backend with any provider (SES, SendGrid, etc.):

```python
from bharatauth.email import set_email_backend

class MyEmailBackend:
    def send(self, *, to, subject, body_text, body_html=None):
        # your implementation
        my_email_client.send(to=to, subject=subject, body=body_text)

set_email_backend(MyEmailBackend())
```

---

## License

MIT — Copyright JamBuster Technologies Pvt Ltd
