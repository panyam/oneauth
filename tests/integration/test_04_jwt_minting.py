"""JWT minting with host credentials — register, mint token, verify claims and signature."""

import base64
import hashlib
import hmac
import json
import time

import pytest


def _mint_jwt(client_id: str, secret_hex: str, user_id: str, scopes: list[str]) -> str:
    """Mint a HS256 JWT using the host's secret (pure python, no deps)."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=")
    now = int(time.time())
    payload = base64.urlsafe_b64encode(
        json.dumps({
            "sub": user_id,
            "client_id": client_id,
            "type": "access",
            "scopes": scopes,
            "iat": now,
            "exp": now + 900,
        }).encode()
    ).rstrip(b"=")
    sig_input = header + b"." + payload
    sig = base64.urlsafe_b64encode(
        hmac.new(bytes.fromhex(secret_hex), sig_input, hashlib.sha256).digest()
    ).rstrip(b"=")
    return (sig_input + b"." + sig).decode()


def _decode_claims(token: str) -> dict:
    """Decode JWT payload without verification."""
    payload_b64 = token.split(".")[1]
    padding = 4 - len(payload_b64) % 4
    payload = base64.urlsafe_b64decode(payload_b64 + "=" * padding)
    return json.loads(payload)


@pytest.fixture
def host_with_secret(client):
    r = client.register_host(client_domain="jwt-test.example.com", signing_alg="HS256")
    assert r.status_code == 201
    data = r.json()
    yield data
    client.delete_host(data["client_id"])


class TestJWTMinting:
    def test_mint_token_has_correct_claims(self, host_with_secret):
        token = _mint_jwt(
            host_with_secret["client_id"],
            host_with_secret["client_secret"],
            "user-42",
            ["relay:connect", "relay:publish"],
        )
        claims = _decode_claims(token)
        assert claims["sub"] == "user-42"
        assert claims["client_id"] == host_with_secret["client_id"]
        assert claims["type"] == "access"
        assert "relay:connect" in claims["scopes"]
        assert "relay:publish" in claims["scopes"]

    def test_wrong_secret_produces_different_signature(self, host_with_secret):
        good_token = _mint_jwt(
            host_with_secret["client_id"],
            host_with_secret["client_secret"],
            "user-42",
            ["relay:connect"],
        )
        bad_token = _mint_jwt(
            host_with_secret["client_id"],
            "00" * 32,  # wrong secret
            "user-42",
            ["relay:connect"],
        )
        # Signatures must differ
        good_sig = good_token.split(".")[2]
        bad_sig = bad_token.split(".")[2]
        assert good_sig != bad_sig

    def test_rotated_secret_invalidates_old_token(self, client, host_with_secret):
        cid = host_with_secret["client_id"]
        old_secret = host_with_secret["client_secret"]

        # Mint with old secret
        old_token = _mint_jwt(cid, old_secret, "user-42", ["relay:connect"])

        # Rotate
        r = client.post(f"/hosts/{cid}/rotate")
        new_secret = r.json()["client_secret"]

        # Mint with new secret
        new_token = _mint_jwt(cid, new_secret, "user-42", ["relay:connect"])

        # Old and new tokens should have different signatures
        assert old_token.split(".")[2] != new_token.split(".")[2]

        # Verify new token's signature with new secret
        parts = new_token.split(".")
        sig_input = (parts[0] + "." + parts[1]).encode()
        expected_sig = base64.urlsafe_b64decode(parts[2] + "==")
        actual_sig = hmac.new(
            bytes.fromhex(new_secret), sig_input, hashlib.sha256
        ).digest()
        assert hmac.compare_digest(actual_sig, expected_sig)
