import logging
import os
import time
import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Header, HTTPException


logger = logging.getLogger("secure_review.auth")


@dataclass
class _JwksCache:
    url: str
    keys: list[dict]
    expires_at: float


_jwks_cache: _JwksCache | None = None
_jwks_lock = threading.Lock()
_SUPPORTED_JWKS_ALGORITHMS = {
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
}


def _configuration_error() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail="Authentication is not configured",
    )


def _jwks_unavailable_error() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail="Authentication provider is unavailable",
    )


def _claims_options() -> tuple[str | None, str | None]:
    return (
        os.getenv("SUPABASE_JWT_ISSUER"),
        os.getenv("SUPABASE_JWT_AUDIENCE"),
    )


def _supabase_url() -> str:
    configured_url = os.getenv("SUPABASE_URL")
    if configured_url:
        return configured_url.strip()
    if os.getenv("APP_ENV", "development").lower() != "development":
        return ""

    configured_url = os.getenv("VITE_SUPABASE_URL")
    if configured_url:
        return configured_url.strip()

    return _read_local_supabase_url(
        Path(__file__).resolve().parents[2] / ".env.local"
    )


def _read_local_supabase_url(path: Path) -> str:
    try:
        with path.open(encoding="utf-8") as environment_file:
            for line in environment_file:
                name, separator, value = line.partition("=")
                if separator and name.strip() == "VITE_SUPABASE_URL":
                    return value.strip().strip("\"'")
    except OSError:
        return ""
    return ""


def _jwt_mode() -> str:
    configured_mode = os.getenv("SUPABASE_JWT_MODE")
    if configured_mode:
        return configured_mode.lower()
    return "jwks" if _supabase_url() else "hs256"


def _jwks_configuration() -> tuple[str, str, str] | None:
    supabase_url = _supabase_url().rstrip("/")
    project = urlsplit(supabase_url)
    if (
        supabase_url
        and (
            project.scheme != "https"
            or not project.hostname
            or project.username
            or project.password
            or project.query
            or project.fragment
            or project.path not in ("", "/")
        )
    ):
        return None

    project_url = f"{project.scheme}://{project.netloc}" if project.hostname else ""
    jwks_url = os.getenv("SUPABASE_JWKS_URL") or (
        f"{project_url}/auth/v1/.well-known/jwks.json" if project_url else ""
    )
    issuer = os.getenv("SUPABASE_JWT_ISSUER") or (
        f"{project_url}/auth/v1" if project_url else ""
    )
    audience = os.getenv("SUPABASE_JWT_AUDIENCE") or (
        "authenticated" if project_url else ""
    )

    jwks = urlsplit(jwks_url)
    issuer_url = urlsplit(issuer)
    if (
        not jwks_url
        or jwks.scheme != "https"
        or not jwks.hostname
        or jwks.username
        or jwks.password
        or jwks.query
        or jwks.fragment
        or not issuer
        or issuer_url.scheme != "https"
        or not issuer_url.hostname
        or issuer_url.username
        or issuer_url.password
        or issuer_url.query
        or issuer_url.fragment
        or not audience
    ):
        return None
    return jwks_url, issuer, audience


def _jwks_algorithms() -> list[str]:
    return [
        item.strip()
        for item in os.getenv("SUPABASE_JWT_ALLOWED_ALGORITHMS", "ES256,RS256").split(",")
        if item.strip()
    ]


def auth_is_configured() -> bool:
    mode = _jwt_mode()
    if mode == "hs256":
        return bool(os.getenv("SUPABASE_JWT_SECRET"))
    if mode == "jwks":
        algorithms = _jwks_algorithms()
        return (
            _jwks_configuration() is not None
            and bool(algorithms)
            and all(algorithm in _SUPPORTED_JWKS_ALGORITHMS for algorithm in algorithms)
        )
    return False


def _load_jwks(url: str, force_refresh: bool = False) -> list[dict]:
    global _jwks_cache

    now = time.time()

    with _jwks_lock:
        if (
            not force_refresh
            and _jwks_cache
            and _jwks_cache.url == url
            and _jwks_cache.expires_at > now
        ):
            return _jwks_cache.keys

        timeout = max(
            0.5,
            float(os.getenv("SUPABASE_JWKS_TIMEOUT_SECONDS", "3")),
        )

        try:
            request = urllib.request.Request(
                url,
                headers={"Accept": "application/json"},
            )

            with urllib.request.urlopen(
                request,
                timeout=timeout,
            ) as response:
                payload = json.loads(response.read())

            keys = payload.get("keys")

            if not isinstance(keys, list) or not keys:
                raise ValueError("JWKS response did not contain keys")

        except (
            OSError,
            ValueError,
            json.JSONDecodeError,
            urllib.error.URLError,
        ):
            raise _jwks_unavailable_error() from None

        max_age = min(
            900,
            max(
                30,
                int(
                    os.getenv(
                        "SUPABASE_JWKS_CACHE_SECONDS",
                        "300",
                    )
                ),
            ),
        )

        _jwks_cache = _JwksCache(
            url=url,
            keys=keys,
            expires_at=now + max_age,
        )

        return keys


def _verify_jwks(
    token: str,
    issuer: str | None,
    audience: str | None,
) -> str:
    configuration = _jwks_configuration()
    if configuration is None:
        raise _configuration_error()
    url, configured_issuer, configured_audience = configuration
    issuer = issuer or configured_issuer
    audience = audience or configured_audience

    try:
        import jwt
        from jwt import InvalidTokenError
    except ImportError:
        raise _configuration_error() from None

    try:
        header = jwt.get_unverified_header(token)

        algorithm = header.get("alg")
        kid = header.get("kid")

        allowed = _jwks_algorithms()

        if (
            algorithm not in allowed
            or algorithm == "none"
            or not kid
        ):
            raise InvalidTokenError("unsupported token")

        keys = _load_jwks(url)

        key = next(
            (
                item
                for item in keys
                if item.get("kid") == kid
            ),
            None,
        )

        # Refresh JWKS in case Supabase rotated its signing key.
        if key is None:
            key = next(
                (
                    item
                    for item in _load_jwks(
                        url,
                        force_refresh=True,
                    )
                    if item.get("kid") == kid
                ),
                None,
            )

        if (
            not key
            or key.get("use", "sig") != "sig"
            or key.get("alg", algorithm) != algorithm
        ):
            raise InvalidTokenError("untrusted key")

        kty = key.get("kty")

        # RSA: RS256/RS384/RS512 and PS256/PS384/PS512
        if algorithm.startswith("RS") or algorithm.startswith("PS"):
            if kty != "RSA":
                raise InvalidTokenError("untrusted key")

            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(
                json.dumps(key)
            )

        # EC: ES256/ES384/ES512
        elif algorithm.startswith("ES"):
            if kty != "EC":
                raise InvalidTokenError("untrusted key")

            public_key = jwt.algorithms.ECAlgorithm.from_jwk(
                json.dumps(key)
            )

        else:
            raise InvalidTokenError(
                "unsupported token algorithm"
            )

        claims = jwt.decode(
            token,
            public_key,
            algorithms=[algorithm],
            issuer=issuer,
            audience=audience,
            options={
                "require": [
                    "sub",
                    "exp",
                ]
            },
            leeway=5,
        )

        subject = claims.get("sub")

        if not isinstance(subject, str) or not subject:
            raise InvalidTokenError("missing subject")

        return subject

    except HTTPException:
        raise

    except (
        ValueError,
        TypeError,
        KeyError,
        InvalidTokenError,
    ) as exc:
        logger.warning(
            "jwt_verification_failed",
            extra={"mode": "jwks", "error_type": type(exc).__name__},
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token",
        ) from None


def verify_token(
    authorization: str | None,
) -> str:
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    token = authorization[7:].strip()

    if not token:
        print("AUTH DEBUG: Bearer token is empty")

        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    mode = _jwt_mode()

    issuer, audience = _claims_options()

    if mode == "jwks":
        return _verify_jwks(
            token,
            issuer,
            audience,
        )

    if mode != "hs256":
        raise _configuration_error()

    secret = os.getenv("SUPABASE_JWT_SECRET")

    if not secret:
        raise _configuration_error()

    try:
        import jwt
        from jwt import InvalidTokenError

        claims = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            issuer=issuer,
            audience=audience,
            options={
                "require": [
                    "sub",
                    "exp",
                ],
                "verify_iss": bool(issuer),
                "verify_aud": bool(audience),
            },
            leeway=5,
        )

    except ImportError:
        raise _configuration_error() from None

    except InvalidTokenError as exc:
        logger.warning(
            "jwt_verification_failed",
            extra={"mode": "hs256", "error_type": type(exc).__name__},
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token",
        ) from None

    subject = claims.get("sub")

    if not isinstance(subject, str) or not subject:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token",
        )

    return subject


def current_user(
    authorization: str | None = Header(default=None),
) -> str:
    return verify_token(authorization)