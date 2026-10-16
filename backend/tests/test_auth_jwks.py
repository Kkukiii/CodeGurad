import base64
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from app import auth


SECRET = "test-only-secret-32-bytes-long!!"


@pytest.fixture(autouse=True)
def isolate_jwks_algorithm_configuration(monkeypatch):
    monkeypatch.setenv("SUPABASE_JWT_ALLOWED_ALGORITHMS", "RS256")


def _b64(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _key_material():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_numbers()
    jwk = {"kty": "RSA", "n": _b64(public.n), "e": _b64(public.e), "alg": "RS256", "use": "sig", "kid": "key-1"}
    return private, {"keys": [jwk]}


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self):
        return json.dumps(self.payload).encode()


def test_hs256_rejects_expired_token(monkeypatch):
    monkeypatch.setenv("SUPABASE_JWT_MODE", "hs256")
    monkeypatch.setenv("SUPABASE_JWT_SECRET", SECRET)
    token = jwt.encode({"sub": "user", "exp": int(time.time()) - 10}, SECRET, algorithm="HS256")
    with pytest.raises(HTTPException) as error:
        auth.verify_token(f"Bearer {token}")
    assert error.value.status_code == 401


def test_jwks_validates_rsa_key_and_claims(monkeypatch):
    private, payload = _key_material()
    auth._jwks_cache = None
    monkeypatch.setenv("SUPABASE_JWT_MODE", "jwks")
    monkeypatch.setenv("SUPABASE_JWKS_URL", "https://issuer.example/jwks")
    monkeypatch.setenv("SUPABASE_JWT_ISSUER", "https://issuer.example")
    monkeypatch.setenv("SUPABASE_JWT_AUDIENCE", "authenticated")
    monkeypatch.setattr(auth.urllib.request, "urlopen", lambda request, timeout: _Response(payload))
    token = jwt.encode({"sub": "user", "exp": int(time.time()) + 300, "iss": "https://issuer.example", "aud": "authenticated"}, private, algorithm="RS256", headers={"kid": "key-1"})
    assert auth.verify_token(f"Bearer {token}") == "user"


def test_jwks_unknown_kid_refreshes_then_rejects(monkeypatch):
    private, payload = _key_material()
    auth._jwks_cache = None
    calls = []
    monkeypatch.setenv("SUPABASE_JWT_MODE", "jwks")
    monkeypatch.setenv("SUPABASE_JWKS_URL", "https://issuer.example/jwks-unknown")
    monkeypatch.setenv("SUPABASE_JWT_ISSUER", "https://issuer.example")
    monkeypatch.setenv("SUPABASE_JWT_AUDIENCE", "authenticated")
    monkeypatch.setattr(auth.urllib.request, "urlopen", lambda request, timeout: (calls.append(1) or _Response(payload)))
    token = jwt.encode({"sub": "user", "exp": int(time.time()) + 300, "iss": "https://issuer.example", "aud": "authenticated"}, private, algorithm="RS256", headers={"kid": "unknown"})
    with pytest.raises(HTTPException) as error:
        auth.verify_token(f"Bearer {token}")
    assert error.value.status_code == 401
    assert len(calls) == 2


def test_jwks_outage_fails_closed(monkeypatch):
    private, _ = _key_material()
    auth._jwks_cache = None
    monkeypatch.setenv("SUPABASE_JWT_MODE", "jwks")
    monkeypatch.setenv("SUPABASE_JWKS_URL", "https://issuer.example/jwks-outage")
    monkeypatch.setenv("SUPABASE_JWT_ISSUER", "https://issuer.example")
    monkeypatch.setenv("SUPABASE_JWT_AUDIENCE", "authenticated")
    def outage(request, timeout):
        raise OSError("network unavailable")
    monkeypatch.setattr(auth.urllib.request, "urlopen", outage)
    with pytest.raises(HTTPException) as error:
        token = jwt.encode({"sub": "user", "exp": int(time.time()) + 300, "iss": "https://issuer.example", "aud": "authenticated"}, private, algorithm="RS256", headers={"kid": "key-1"})
        auth.verify_token(f"Bearer {token}")
    assert error.value.status_code == 503


def test_jwks_rejects_none_algorithm(monkeypatch):
    monkeypatch.setenv("SUPABASE_JWT_MODE", "jwks")
    monkeypatch.setenv("SUPABASE_JWKS_URL", "https://issuer.example/jwks-none")
    monkeypatch.setenv("SUPABASE_JWT_ISSUER", "https://issuer.example")
    monkeypatch.setenv("SUPABASE_JWT_AUDIENCE", "authenticated")
    token = jwt.encode({"sub": "user", "exp": int(time.time()) + 300, "iss": "https://issuer.example", "aud": "authenticated"}, key="", algorithm="none")
    with pytest.raises(HTTPException) as error:
        auth.verify_token(f"Bearer {token}")
    assert error.value.status_code == 401
