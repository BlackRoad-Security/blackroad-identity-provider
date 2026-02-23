"""Tests for blackroad-identity-provider."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from src.identity_provider import (
    IdentityProvider, create_token, verify_token,
    hash_password, verify_password, generate_totp_secret, verify_totp,
)


@pytest.fixture
def idp(tmp_path):
    secret = b"test-secret-key-32bytes!!!!!!!!"
    return IdentityProvider(str(tmp_path / "test_idp.db"), secret)


def test_register_and_login(idp):
    idp.register("alice", "alice@test.com", "Str0ng!Pass#1")
    result = idp.authenticate("alice", "Str0ng!Pass#1")
    assert result["success"]
    assert "access_token" in result


def test_wrong_password(idp):
    idp.register("bob", "bob@test.com", "Str0ng!Pass#2")
    result = idp.authenticate("bob", "wrongpassword")
    assert not result["success"]


def test_weak_password_rejected(idp):
    result = idp.register("charlie", "c@test.com", "weak")
    assert not result["success"]
    assert len(result["errors"]) > 0


def test_token_verification(idp):
    idp.register("dave", "dave@test.com", "Str0ng!Pass#4")
    login = idp.authenticate("dave", "Str0ng!Pass#4")
    ok, payload = idp.verify(login["access_token"])
    assert ok
    assert payload["username"] == "dave"


def test_invalid_token(idp):
    ok, payload = idp.verify("bad.token.value")
    assert not ok


def test_account_lockout(idp):
    idp.register("eve", "eve@test.com", "Str0ng!Pass#5")
    for _ in range(5):
        idp.authenticate("eve", "wrongpassword")
    result = idp.authenticate("eve", "Str0ng!Pass#5")
    assert not result["success"]
    assert "locked" in result["error"].lower()


def test_totp_roundtrip():
    secret = generate_totp_secret()
    from src.identity_provider import generate_totp
    code = generate_totp(secret)
    assert verify_totp(secret, code)


def test_audit_log(idp):
    idp.register("frank", "frank@test.com", "Str0ng!Pass#6")
    idp.authenticate("frank", "Str0ng!Pass#6")
    log = idp.get_audit_log("frank")
    assert len(log) >= 1
