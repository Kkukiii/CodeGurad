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
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("VITE_SUPABASE_URL", raising=False)


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


def test_jwks_derives_standard_settings_from_supabase_url(monkeypatch):
    private, payload = _key_material()
    auth._jwks_cache = None
    monkeypatch.delenv("SUPABASE_JWT_MODE", raising=False)
    monkeypatch.delenv("SUPABASE_JWKS_URL", raising=False)
    monkeypatch.delenv("SUPABASE_JWT_ISSUER", raising=False)
    monkeypatch.delenv("SUPABASE_JWT_AUDIENCE", raising=False)
    monkeypatch.setenv("SUPABASE_URL", "https://project.example.supabase.co/")
    monkeypatch.setattr(auth.urllib.request, "urlopen", lambda request, timeout: _Response(payload))
    token = jwt.encode(
        {
            "sub": "user",
            "exp": int(time.time()) + 300,
            "iss": "https://project.example.supabase.co/auth/v1",
            "aud": "authenticated",
        },
        private,
        algorithm="RS256",
        headers={"kid": "key-1"},
    )

    assert auth.auth_is_configured()
    assert auth.verify_token(f"Bearer {token}") == "user"


def test_local_jwks_uses_frontend_project_url_when_backend_url_is_unset(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_JWT_MODE", raising=False)
    monkeypatch.delenv("SUPABASE_JWKS_URL", raising=False)
    monkeypatch.delenv("SUPABASE_JWT_ISSUER", raising=False)
    monkeypatch.delenv("SUPABASE_JWT_AUDIENCE", raising=False)
    monkeypatch.setenv("VITE_SUPABASE_URL", "https://project.example.supabase.co")

    assert auth.auth_is_configured()
    assert auth._jwks_configuration() == (
        "https://project.example.supabase.co/auth/v1/.well-known/jwks.json",
        "https://project.example.supabase.co/auth/v1",
        "authenticated",
    )


def test_local_env_reader_returns_only_public_project_url(tmp_path):
    environment_file = tmp_path / ".env.local"
    environment_file.write_text(
        "VITE_SUPABASE_PUBLISHABLE_KEY=do-not-return-this\n"
        "VITE_SUPABASE_URL='https://project.example.supabase.co'\n",
        encoding="utf-8",
    )

    assert auth._read_local_supabase_url(environment_file) == "https://project.example.supabase.co"


def test_production_does_not_load_frontend_local_environment(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.setenv("VITE_SUPABASE_URL", "https://frontend-project.example.supabase.co")
    monkeypatch.delenv("SUPABASE_JWT_MODE", raising=False)

    def reject_local_environment(_path):
        raise AssertionError("local env must not be read")

    monkeypatch.setattr(auth, "_read_local_supabase_url", reject_local_environment)

    assert not auth.auth_is_configured()


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
    assert error.value.detail == "Authentication provider is unavailable"


def test_jwks_rejects_none_algorithm(monkeypatch):
    monkeypatch.setenv("SUPABASE_JWT_MODE", "jwks")
    monkeypatch.setenv("SUPABASE_JWKS_URL", "https://issuer.example/jwks-none")
    monkeypatch.setenv("SUPABASE_JWT_ISSUER", "https://issuer.example")
    monkeypatch.setenv("SUPABASE_JWT_AUDIENCE", "authenticated")
    token = jwt.encode({"sub": "user", "exp": int(time.time()) + 300, "iss": "https://issuer.example", "aud": "authenticated"}, key="", algorithm="none")
    with pytest.raises(HTTPException) as error:
        auth.verify_token(f"Bearer {token}")
    assert error.value.status_code == 401
