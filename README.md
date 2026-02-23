# blackroad-identity-provider

Stdlib-only Identity Provider with JWT tokens, PBKDF2 passwords, TOTP MFA, session management and audit logging.

## Features

- 🎫 **JWT Tokens** – HS256-signed tokens (header.payload.signature format, JWT-compatible)
- 🔑 **PBKDF2 Passwords** – 310,000 iterations, random salt, constant-time verification
- 📱 **TOTP MFA** – RFC 6238 TOTP (works with Google Authenticator, Authy)
- 🔒 **Account Lockout** – 5 failed attempts triggers 5-minute lockout
- 💪 **Password Policy** – Minimum 12 chars, uppercase, lowercase, digit, special char
- 📝 **Audit Log** – Every login/register/MFA event logged with timestamp and IP

## Stdlib Only

Uses: `hashlib`, `hmac`, `base64`, `sqlite3`, `os`, `time`, `secrets`

## Usage

```bash
# Register a user
python src/identity_provider.py register alice alice@example.com "Str0ng!Pass#1"

# Login
python src/identity_provider.py login alice "Str0ng!Pass#1"

# Verify a token
python src/identity_provider.py verify "eyJ..."

# Enable MFA
python src/identity_provider.py enable-mfa u_abc123

# List users
python src/identity_provider.py list-users

# Audit log
python src/identity_provider.py audit --user alice
```

## Token Format

```json
{
  "header": {"alg": "HS256", "typ": "JWT"},
  "payload": {"sub": "user_id", "username": "alice", "roles": ["viewer"], "iat": ..., "exp": ...}
}
```

## Tests

```bash
pytest tests/ -v --cov=src
```

## License

Proprietary – BlackRoad OS, Inc. All rights reserved.