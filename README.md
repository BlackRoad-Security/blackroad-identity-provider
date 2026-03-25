<!-- BlackRoad SEO Enhanced -->

# ulackroad identity provider

> Part of **[BlackRoad OS](https://blackroad.io)** — Sovereign Computing for Everyone

[![BlackRoad OS](https://img.shields.io/badge/BlackRoad-OS-ff1d6c?style=for-the-badge)](https://blackroad.io)
[![BlackRoad Security](https://img.shields.io/badge/Org-BlackRoad-Security-2979ff?style=for-the-badge)](https://github.com/BlackRoad-Security)
[![License](https://img.shields.io/badge/License-Proprietary-f5a623?style=for-the-badge)](LICENSE)

**ulackroad identity provider** is part of the **BlackRoad OS** ecosystem — a sovereign, distributed operating system built on edge computing, local AI, and mesh networking by **BlackRoad OS, Inc.**

## About BlackRoad OS

BlackRoad OS is a sovereign computing platform that runs AI locally on your own hardware. No cloud dependencies. No API keys. No surveillance. Built by [BlackRoad OS, Inc.](https://github.com/BlackRoad-OS-Inc), a Delaware C-Corp founded in 2025.

### Key Features
- **Local AI** — Run LLMs on Raspberry Pi, Hailo-8, and commodity hardware
- **Mesh Networking** — WireGuard VPN, NATS pub/sub, peer-to-peer communication
- **Edge Computing** — 52 TOPS of AI acceleration across a Pi fleet
- **Self-Hosted Everything** — Git, DNS, storage, CI/CD, chat — all sovereign
- **Zero Cloud Dependencies** — Your data stays on your hardware

### The BlackRoad Ecosystem
| Organization | Focus |
|---|---|
| [BlackRoad OS](https://github.com/BlackRoad-OS) | Core platform and applications |
| [BlackRoad OS, Inc.](https://github.com/BlackRoad-OS-Inc) | Corporate and enterprise |
| [BlackRoad AI](https://github.com/BlackRoad-AI) | Artificial intelligence and ML |
| [BlackRoad Hardware](https://github.com/BlackRoad-Hardware) | Edge hardware and IoT |
| [BlackRoad Security](https://github.com/BlackRoad-Security) | Cybersecurity and auditing |
| [BlackRoad Quantum](https://github.com/BlackRoad-Quantum) | Quantum computing research |
| [BlackRoad Agents](https://github.com/BlackRoad-Agents) | Autonomous AI agents |
| [BlackRoad Network](https://github.com/BlackRoad-Network) | Mesh and distributed networking |
| [BlackRoad Education](https://github.com/BlackRoad-Education) | Learning and tutoring platforms |
| [BlackRoad Labs](https://github.com/BlackRoad-Labs) | Research and experiments |
| [BlackRoad Cloud](https://github.com/BlackRoad-Cloud) | Self-hosted cloud infrastructure |
| [BlackRoad Forge](https://github.com/BlackRoad-Forge) | Developer tools and utilities |

### Links
- **Website**: [blackroad.io](https://blackroad.io)
- **Documentation**: [docs.blackroad.io](https://docs.blackroad.io)
- **Chat**: [chat.blackroad.io](https://chat.blackroad.io)
- **Search**: [search.blackroad.io](https://search.blackroad.io)

---


> BlackRoad Security - ublackroad identity provider

Part of the [BlackRoad OS](https://blackroad.io) ecosystem — [BlackRoad-Security](https://github.com/BlackRoad-Security)

---

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
