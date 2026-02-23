"""
BlackRoad Identity Provider – JWT-like token service with RBAC, MFA, sessions.
Stdlib-only: hashlib, hmac, base64, json, sqlite3, os, time.
No third-party dependencies.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple


# ─────────────────────────────────────────────
# Token (JWT-compatible HMAC-SHA256 format)
# ─────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def create_token(payload: Dict[str, Any], secret: bytes,
                 expires_in: int = 3600) -> str:
    """Create a signed HS256 token (JWT-compatible format)."""
    now = int(time.time())
    payload = {**payload, "iat": now, "exp": now + expires_in, "jti": secrets.token_hex(8)}
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url_encode(json.dumps(payload).encode())
    sig_input = f"{header}.{body}".encode()
    sig = hmac.new(secret, sig_input, hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url_encode(sig)}"


def verify_token(token: str, secret: bytes) -> Tuple[bool, Dict[str, Any]]:
    """Verify token signature and expiry. Returns (valid, payload)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False, {"error": "malformed token"}
        header_b64, body_b64, sig_b64 = parts
        expected_sig = hmac.new(
            secret, f"{header_b64}.{body_b64}".encode(), hashlib.sha256
        ).digest()
        actual_sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, actual_sig):
            return False, {"error": "invalid signature"}
        payload = json.loads(_b64url_decode(body_b64))
        if payload.get("exp", 0) < time.time():
            return False, {"error": "token expired", "exp": payload.get("exp")}
        return True, payload
    except Exception as e:
        return False, {"error": str(e)}


def decode_token_unsafe(token: str) -> Dict[str, Any]:
    """Decode token payload WITHOUT verifying signature (for inspection only)."""
    try:
        _, body_b64, _ = token.split(".")
        return json.loads(_b64url_decode(body_b64))
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────
# Password utilities
# ─────────────────────────────────────────────

def hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256 with random salt."""
    salt = os.urandom(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"pbkdf2$310000${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters_s, salt_b64, dk_b64 = stored.split("$")
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        computed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iters_s))
        return hmac.compare_digest(computed, expected)
    except Exception:
        return False


def _validate_password_strength(password: str) -> List[str]:
    """Return list of policy violations."""
    issues = []
    if len(password) < 12:
        issues.append("Too short (min 12 chars)")
    if not re.search(r"[A-Z]", password):
        issues.append("Missing uppercase letter")
    if not re.search(r"[a-z]", password):
        issues.append("Missing lowercase letter")
    if not re.search(r"\d", password):
        issues.append("Missing digit")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        issues.append("Missing special character")
    return issues


# ─────────────────────────────────────────────
# TOTP MFA (RFC 6238 compliant)
# ─────────────────────────────────────────────

def _hotp(secret: bytes, counter: int) -> int:
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = ((digest[offset] & 0x7F) << 24 |
            (digest[offset+1] & 0xFF) << 16 |
            (digest[offset+2] & 0xFF) << 8 |
            (digest[offset+3] & 0xFF))
    return code % 10**6


def generate_totp(secret_b32: str, digits: int = 6, step: int = 30) -> str:
    """Generate current TOTP code."""
    secret = base64.b32decode(secret_b32.upper().replace(" ", ""))
    counter = int(time.time()) // step
    return str(_hotp(secret, counter)).zfill(digits)


def verify_totp(secret_b32: str, code: str, window: int = 1, step: int = 30) -> bool:
    """Verify TOTP code with drift window."""
    secret = base64.b32decode(secret_b32.upper().replace(" ", ""))
    counter = int(time.time()) // step
    for delta in range(-window, window + 1):
        expected = str(_hotp(secret, counter + delta)).zfill(6)
        if hmac.compare_digest(expected, code.zfill(6)):
            return True
    return False


def generate_totp_secret() -> str:
    """Generate a new base32 TOTP secret."""
    return base64.b32encode(os.urandom(20)).decode()


# ─────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id             TEXT PRIMARY KEY,
    username       TEXT UNIQUE NOT NULL,
    email          TEXT UNIQUE NOT NULL,
    password_hash  TEXT NOT NULL,
    roles          TEXT DEFAULT '[]',
    totp_secret    TEXT DEFAULT NULL,
    mfa_enabled    INTEGER DEFAULT 0,
    active         INTEGER DEFAULT 1,
    failed_logins  INTEGER DEFAULT 0,
    locked_until   TEXT DEFAULT NULL,
    created_at     TEXT DEFAULT (datetime('now')),
    last_login     TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    token_hash  TEXT NOT NULL,
    ip_address  TEXT DEFAULT '',
    user_agent  TEXT DEFAULT '',
    created_at  TEXT DEFAULT (datetime('now')),
    expires_at  TEXT NOT NULL,
    revoked     INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    user_id     TEXT,
    username    TEXT,
    event       TEXT NOT NULL,
    ip_address  TEXT DEFAULT '',
    detail      TEXT DEFAULT '',
    success     INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
"""


class IdentityDB:
    def __init__(self, path: str = "identity.db"):
        self.path = path
        with self._conn() as c:
            c.executescript(DB_SCHEMA)

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


# ─────────────────────────────────────────────
# Identity Provider
# ─────────────────────────────────────────────

MAX_FAILED = 5
LOCKOUT_SECONDS = 300


class IdentityProvider:
    def __init__(self, db_path: str = "identity.db", token_secret: Optional[bytes] = None):
        self.db = IdentityDB(db_path)
        self.secret = token_secret or os.urandom(32)

    # ── User management ──────────────────────

    def register(self, username: str, email: str, password: str,
                 roles: Optional[List[str]] = None) -> Dict[str, Any]:
        issues = _validate_password_strength(password)
        if issues:
            return {"success": False, "errors": issues}
        uid = "u_" + secrets.token_hex(8)
        ph = hash_password(password)
        roles_list = roles or ["viewer"]
        with self.db._conn() as conn:
            try:
                conn.execute(
                    "INSERT INTO users (id,username,email,password_hash,roles) VALUES (?,?,?,?,?)",
                    (uid, username, email, ph, json.dumps(roles_list)),
                )
            except sqlite3.IntegrityError as e:
                return {"success": False, "errors": [str(e)]}
        self._audit(conn=None, user_id=uid, username=username,
                    event="REGISTER", detail=f"email={email}", success=True)
        return {"success": True, "user_id": uid, "username": username}

    def authenticate(self, username: str, password: str,
                     totp_code: Optional[str] = None,
                     ip_address: str = "") -> Dict[str, Any]:
        with self.db._conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if not row:
                self._audit_raw(conn, None, username, "LOGIN_FAIL", ip_address,
                                "user not found", False)
                return {"success": False, "error": "Invalid credentials"}

            # Lockout check
            locked_until = row["locked_until"]
            if locked_until:
                lu = datetime.fromisoformat(locked_until)
                if lu > datetime.now(timezone.utc):
                    return {"success": False, "error": "Account locked",
                            "locked_until": locked_until}

            if not row["active"]:
                return {"success": False, "error": "Account disabled"}

            # Password check
            if not verify_password(password, row["password_hash"]):
                fails = row["failed_logins"] + 1
                locked = None
                if fails >= MAX_FAILED:
                    locked = datetime.fromtimestamp(
                        time.time() + LOCKOUT_SECONDS, tz=timezone.utc
                    ).isoformat()
                conn.execute(
                    "UPDATE users SET failed_logins=?, locked_until=? WHERE id=?",
                    (fails, locked, row["id"]),
                )
                self._audit_raw(conn, row["id"], username, "LOGIN_FAIL",
                                ip_address, "bad password", False)
                return {"success": False, "error": "Invalid credentials"}

            # MFA check
            if row["mfa_enabled"] and row["totp_secret"]:
                if not totp_code:
                    return {"success": False, "error": "MFA required", "mfa_required": True}
                if not verify_totp(row["totp_secret"], totp_code):
                    self._audit_raw(conn, row["id"], username, "MFA_FAIL",
                                    ip_address, "invalid TOTP", False)
                    return {"success": False, "error": "Invalid MFA code"}

            # Success – reset fails, create session
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "UPDATE users SET failed_logins=0, locked_until=NULL, last_login=? WHERE id=?",
                (now, row["id"]),
            )
            roles = json.loads(row["roles"] or "[]")
            payload = {"sub": row["id"], "username": username, "roles": roles}
            token = create_token(payload, self.secret, expires_in=3600)
            session_id = "s_" + secrets.token_hex(8)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            exp = datetime.fromtimestamp(
                time.time() + 3600, tz=timezone.utc
            ).isoformat()
            conn.execute(
                "INSERT INTO sessions (id,user_id,token_hash,ip_address,expires_at) "
                "VALUES (?,?,?,?,?)",
                (session_id, row["id"], token_hash, ip_address, exp),
            )
            self._audit_raw(conn, row["id"], username, "LOGIN_OK", ip_address, "", True)
        return {
            "success": True,
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 3600,
            "session_id": session_id,
            "user": {"id": row["id"], "username": username, "roles": roles},
        }

    def verify(self, token: str) -> Tuple[bool, Dict[str, Any]]:
        return verify_token(token, self.secret)

    def logout(self, session_id: str) -> bool:
        with self.db._conn() as conn:
            cur = conn.execute("UPDATE sessions SET revoked=1 WHERE id=?", (session_id,))
            return cur.rowcount > 0

    def enable_mfa(self, user_id: str) -> Dict[str, Any]:
        secret = generate_totp_secret()
        with self.db._conn() as conn:
            conn.execute(
                "UPDATE users SET totp_secret=?, mfa_enabled=1 WHERE id=?",
                (secret, user_id),
            )
        return {"totp_secret": secret, "message": "Store this secret in your authenticator app"}

    def list_users(self, limit: int = 50) -> List[Dict]:
        with self.db._conn() as conn:
            rows = conn.execute(
                "SELECT id,username,email,roles,mfa_enabled,active,created_at,last_login "
                "FROM users ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_audit_log(self, username: Optional[str] = None, limit: int = 50) -> List[Dict]:
        with self.db._conn() as conn:
            if username:
                rows = conn.execute(
                    "SELECT * FROM audit_events WHERE username=? ORDER BY id DESC LIMIT ?",
                    (username, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
            return [dict(r) for r in rows]

    def _audit(self, conn, user_id, username, event, detail="", success=True, ip=""):
        with self.db._conn() as c:
            self._audit_raw(c, user_id, username, event, ip, detail, success)

    def _audit_raw(self, conn, user_id, username, event, ip, detail, success):
        ts = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO audit_events (ts,user_id,username,event,ip_address,detail,success) "
            "VALUES (?,?,?,?,?,?,?)",
            (ts, user_id, username, event, ip, detail, int(success)),
        )


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="BlackRoad Identity Provider")
    p.add_argument("--db", default="identity.db")
    p.add_argument("--secret", default=None, help="Token signing secret (hex)")
    sub = p.add_subparsers(dest="cmd")

    rg = sub.add_parser("register", help="Register a user")
    rg.add_argument("username"); rg.add_argument("email"); rg.add_argument("password")
    rg.add_argument("--roles", default="viewer")

    lg = sub.add_parser("login", help="Authenticate a user")
    lg.add_argument("username"); lg.add_argument("password")
    lg.add_argument("--totp", default=None)

    vt = sub.add_parser("verify", help="Verify a token")
    vt.add_argument("token")

    sub.add_parser("list-users", help="List users")

    mfa = sub.add_parser("enable-mfa", help="Enable MFA for user")
    mfa.add_argument("user_id")

    au = sub.add_parser("audit", help="Show audit log")
    au.add_argument("--user", default=None)
    au.add_argument("--limit", type=int, default=20)

    args = p.parse_args(argv)
    secret = bytes.fromhex(args.secret) if args.secret else None
    idp = IdentityProvider(args.db, secret)

    if args.cmd == "register":
        roles = [r.strip() for r in args.roles.split(",")]
        result = idp.register(args.username, args.email, args.password, roles)
        print(json.dumps(result, indent=2))
        return 0 if result["success"] else 1

    elif args.cmd == "login":
        result = idp.authenticate(args.username, args.password, args.totp)
        if result["success"]:
            print(f"✅ Login successful")
            print(f"Token: {result['access_token'][:60]}...")
            print(f"Session: {result['session_id']}")
        else:
            print(f"❌ {result['error']}")
            return 1

    elif args.cmd == "verify":
        ok, payload = idp.verify(args.token)
        if ok:
            print(f"✅ Valid token")
            print(json.dumps(payload, indent=2))
        else:
            print(f"❌ Invalid: {payload.get('error','')}")
            return 1

    elif args.cmd == "list-users":
        users = idp.list_users()
        print(f"{'ID':<20} {'USERNAME':<20} {'EMAIL':<30} {'MFA':>3} {'ACTIVE':>6}")
        print("-" * 80)
        for u in users:
            print(f"{u['id']:<20} {u['username']:<20} {u['email']:<30} "
                  f"{'Y' if u['mfa_enabled'] else 'N':>3} {'Y' if u['active'] else 'N':>6}")

    elif args.cmd == "enable-mfa":
        result = idp.enable_mfa(args.user_id)
        print(f"✅ MFA enabled. TOTP Secret: {result['totp_secret']}")
        print(f"   {result['message']}")

    elif args.cmd == "audit":
        log = idp.get_audit_log(args.user, args.limit)
        for e in log:
            ok = "✅" if e["success"] else "❌"
            print(f"  {ok} {e['ts'][:19]}  {e['event']:<15} {e['username'] or '':<20} {e['detail'][:40]}")

    else:
        p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
