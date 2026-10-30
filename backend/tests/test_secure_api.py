import asyncio
import base64
import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse

from app import scanner
from app import worker
from app.main import RequestControlsMiddleware, app
from app.storage import create_review, get_job, init_db, list_reviews


TEST_SECRET = "test-only-secret-32-bytes-long!!"


@pytest.fixture(autouse=True)
def isolate_hs256_configuration(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("SUPABASE_JWT_MODE", "hs256")
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("VITE_SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_JWKS_URL", raising=False)
    monkeypatch.delenv("SUPABASE_JWT_ISSUER", raising=False)
    monkeypatch.delenv("SUPABASE_JWT_AUDIENCE", raising=False)
    monkeypatch.delenv("PUBLIC_REVIEWS_ENABLED", raising=False)
    monkeypatch.setattr(scanner, "_scanner_executable", lambda name: None)


def token(subject: str, secret: str = TEST_SECRET, extra: dict | None = None) -> str:
    def encode(value: object) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = encode({"alg": "HS256", "typ": "JWT"})
    claims_data = {"sub": subject, "exp": int(time.time()) + 300}
    claims_data.update(extra or {})
    claims = encode(claims_data)
    message = f"{header}.{claims}".encode()
    signature = base64.urlsafe_b64encode(hmac.new(secret.encode(), message, hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{header}.{claims}.{signature}"


def headers(subject: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token(subject)}"}


def run_body_middleware(
    monkeypatch,
    chunks: list[bytes],
    headers: list[tuple[bytes, bytes]] | None = None,
    *,
    disconnect_after_chunks: bool = False,
) -> tuple[int | None, bytes | None, bool, bytes | None]:
    async def execute():
        messages = [
            {
                "type": "http.request",
                "body": chunk,
                "more_body": disconnect_after_chunks or index < len(chunks) - 1,
            }
            for index, chunk in enumerate(chunks)
        ]
        message_index = 0

        async def receive():
            nonlocal message_index
            if message_index < len(messages):
                message = messages[message_index]
                message_index += 1
                return message
            return {"type": "http.disconnect"}

        sent = []
        downstream_called = False

        async def downstream(scope, app_receive, app_send):
            nonlocal downstream_called
            downstream_called = True
            body = bytearray()
            while True:
                message = await app_receive()
                body.extend(message.get("body", b""))
                if not message.get("more_body", False):
                    break
            lifecycle_message = await app_receive()
            await JSONResponse({
                "size": len(body),
                "body": body.decode(),
                "next_receive": lifecycle_message["type"],
            })(scope, app_receive, app_send)

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/test",
            "raw_path": b"/test",
            "query_string": b"",
            "headers": headers or [],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
        }

        async def send(message):
            sent.append(message)

        await RequestControlsMiddleware(downstream)(scope, receive, send)
        response_start = next((message for message in sent if message["type"] == "http.response.start"), None)
        response_body = next((message["body"] for message in sent if message["type"] == "http.response.body"), None)
        request_id = None
        if response_start:
            request_id = next(
                (
                    value for name, value in response_start["headers"]
                    if name.lower() == b"x-request-id"
                ),
                None,
            )
        return (
            response_start["status"] if response_start else None,
            response_body,
            downstream_called,
            request_id,
        )

    monkeypatch.setattr("app.main.enforce_instance_request_limit", lambda client_host: None)
    return asyncio.run(execute())


def test_secure_api_requires_authentication(monkeypatch, tmp_path):
    monkeypatch.setenv("SUPABASE_JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))
    client = TestClient(app)
    assert client.get("/api/v1/reviews").status_code == 401
    assert client.get("/api/v1/reviews", headers={"Authorization": "Bearer invalid"}).status_code == 401


def test_review_submission_with_auth_header_keeps_auth_configuration_errors_server_side(monkeypatch, tmp_path):
    monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))
    client = TestClient(app)
    response = client.post(
        "/api/v1/reviews",
        headers={"Authorization": f"Bearer {token('user-a')}"},
        json={"filename": "app.py", "code": "print('x')"},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "Authentication is not configured"


def test_review_is_persisted_and_owned(monkeypatch, tmp_path):
    monkeypatch.setenv("SUPABASE_JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))
    client = TestClient(app)
    response = client.post("/api/v1/reviews", headers=headers("user-a"), json={
        "filename": "app.py", "code": "cursor.execute(f'SELECT {user_id}')",
    })
    assert response.status_code == 201
    review = response.json()
    assert review["status"] == "completed-with-warnings"
    assert review["job_id"]
    assert client.get("/api/v1/reviews", headers=headers("user-a")).json()[0]["id"] == review["id"]
    assert client.get(f"/api/v1/jobs/{review['job_id']}", headers=headers("user-a")).json()["status"] == "completed-with-warnings"
    assert client.get("/api/v1/reviews", headers=headers("user-b")).json() == []
    assert client.get(f"/api/v1/reviews/{review['id']}", headers=headers("user-b")).status_code == 404
    assert client.get(f"/api/v1/reviews/{review['id']}/findings", headers=headers("user-b")).status_code == 404
    assert client.get(f"/api/v1/jobs/{review['job_id']}", headers=headers("user-b")).status_code == 404
    assert client.delete(f"/api/v1/reviews/{review['id']}", headers=headers("user-b")).status_code == 404
    assert client.delete(f"/api/v1/reviews/{review['id']}", headers=headers("user-a")).status_code == 204
    assert client.get(f"/api/v1/reviews/{review['id']}", headers=headers("user-a")).status_code == 404


def test_ready_health_requires_auth_configuration(monkeypatch, tmp_path):
    monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))
    client = TestClient(app)
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code == 503


def test_ready_health_accepts_supabase_url_for_jwks_configuration(monkeypatch, tmp_path):
    monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
    monkeypatch.delenv("SUPABASE_JWT_MODE", raising=False)
    monkeypatch.setenv("SUPABASE_URL", "https://project.example.supabase.co/")
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))

    response = TestClient(app).get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_ready_health_rejects_non_https_supabase_url(monkeypatch, tmp_path):
    monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
    monkeypatch.delenv("SUPABASE_JWT_MODE", raising=False)
    monkeypatch.setenv("SUPABASE_URL", "http://project.example.supabase.co")
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))

    response = TestClient(app).get("/health/ready")

    assert response.status_code == 503
    assert response.json()["detail"] == "Authentication is not configured"


def test_ready_health_rejects_unsupported_jwks_algorithm(monkeypatch, tmp_path):
    monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
    monkeypatch.setenv("SUPABASE_JWT_MODE", "jwks")
    monkeypatch.setenv("SUPABASE_URL", "https://project.example.supabase.co")
    monkeypatch.setenv("SUPABASE_JWT_ALLOWED_ALGORITHMS", "HS256")
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))

    response = TestClient(app).get("/health/ready")

    assert response.status_code == 503
    assert response.json()["detail"] == "Authentication is not configured"


def test_ready_health_requires_worker_configuration_when_reviews_are_enabled(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SUPABASE_JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("PUBLIC_REVIEWS_ENABLED", "true")
    monkeypatch.setenv("WORKER_MODE", "external")
    monkeypatch.delenv("WORKER_DATABASE_URL", raising=False)
    monkeypatch.setattr("app.main.ensure_db", lambda: None)
    client = TestClient(app)
    response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json()["detail"] == "Review worker is not configured"

    monkeypatch.setenv("WORKER_DATABASE_URL", "worker-database-placeholder")
    assert client.get("/health/ready").status_code == 200


def test_production_review_submissions_are_disabled_by_default(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SUPABASE_JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))
    monkeypatch.delenv("PUBLIC_REVIEWS_ENABLED", raising=False)
    response = TestClient(app).post(
        "/api/v1/reviews",
        headers=headers("user-a"),
        json={"filename": "app.py", "code": "print('x')"},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "Review processing is disabled"
    assert not (tmp_path / "reviews.sqlite3").exists()


def test_request_id_and_jwt_claims_are_validated(monkeypatch, tmp_path):
    monkeypatch.setenv("SUPABASE_JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("SUPABASE_JWT_ISSUER", "https://issuer.example")
    monkeypatch.setenv("SUPABASE_JWT_AUDIENCE", "authenticated")
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))
    client = TestClient(app)
    invalid_claims = {"Authorization": f"Bearer {token('user-a')}"}
    assert client.get("/api/v1/reviews", headers=invalid_claims).status_code == 401
    valid = {"Authorization": f"Bearer {token('user-a', extra={'iss': 'https://issuer.example', 'aud': 'authenticated'})}", "X-Request-ID": "request-123"}
    response = client.get("/api/v1/reviews", headers=valid)
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "request-123"


def test_request_body_limit_is_enforced(monkeypatch):
    monkeypatch.setenv("MAX_REQUEST_BODY_BYTES", "10")
    response = TestClient(app).post("/api/review", json={"filename": "app.py", "code": "print('too large')"})
    assert response.status_code == 413


def test_chunked_request_body_limit_counts_actual_bytes(monkeypatch):
    monkeypatch.setenv("MAX_REQUEST_BODY_BYTES", "5")
    status_code, _, downstream_called, _ = run_body_middleware(
        monkeypatch, [b"1234", b"5678"], [(b"transfer-encoding", b"chunked")]
    )
    assert status_code == 413
    assert not downstream_called


def test_missing_content_length_does_not_bypass_body_limit(monkeypatch):
    monkeypatch.setenv("MAX_REQUEST_BODY_BYTES", "5")
    status_code, _, downstream_called, _ = run_body_middleware(monkeypatch, [b"123456"])
    assert status_code == 413
    assert not downstream_called


def test_underreported_content_length_does_not_bypass_body_limit(monkeypatch):
    monkeypatch.setenv("MAX_REQUEST_BODY_BYTES", "5")
    status_code, _, downstream_called, _ = run_body_middleware(
        monkeypatch, [b"123", b"456"], [(b"content-length", b"1")]
    )
    assert status_code == 413
    assert not downstream_called


def test_overreported_content_length_uses_actual_body_size(monkeypatch):
    monkeypatch.setenv("MAX_REQUEST_BODY_BYTES", "5")
    status_code, body, downstream_called, request_id = run_body_middleware(
        monkeypatch, [b"123"], [(b"content-length", b"100")]
    )
    assert status_code == 200
    assert json.loads(body)["size"] == 3
    assert downstream_called
    assert request_id


def test_normal_body_with_content_length_is_preserved(monkeypatch):
    monkeypatch.setenv("MAX_REQUEST_BODY_BYTES", "5")
    status_code, body, downstream_called, _ = run_body_middleware(
        monkeypatch, [b"12", b"345"], [(b"content-length", b"5")]
    )
    assert status_code == 200
    assert json.loads(body)["size"] == 5
    assert json.loads(body)["body"] == "12345"
    assert json.loads(body)["next_receive"] == "http.disconnect"
    assert downstream_called


def test_empty_stream_chunks_do_not_change_replayed_body(monkeypatch):
    monkeypatch.setenv("MAX_REQUEST_BODY_BYTES", "5")
    status_code, body, downstream_called, _ = run_body_middleware(
        monkeypatch, [b"", b"12", b"", b"345"]
    )
    assert status_code == 200
    assert json.loads(body) == {
        "size": 5,
        "body": "12345",
        "next_receive": "http.disconnect",
    }
    assert downstream_called


def test_disconnect_before_request_body_does_not_invoke_application(monkeypatch):
    status_code, body, downstream_called, request_id = run_body_middleware(
        monkeypatch, [], disconnect_after_chunks=True
    )
    assert status_code is None
    assert body is None
    assert not downstream_called
    assert request_id is None


def test_disconnect_after_partial_body_does_not_invoke_application(monkeypatch):
    status_code, body, downstream_called, request_id = run_body_middleware(
        monkeypatch, [b'{"value":'], disconnect_after_chunks=True
    )
    assert status_code is None
    assert body is None
    assert not downstream_called
    assert request_id is None


def test_disconnect_after_valid_json_prefix_does_not_process_request(monkeypatch):
    status_code, body, downstream_called, request_id = run_body_middleware(
        monkeypatch, [b'{"value": 1}'], disconnect_after_chunks=True
    )
    assert status_code is None
    assert body is None
    assert not downstream_called
    assert request_id is None


def test_complete_empty_body_is_forwarded_to_application(monkeypatch):
    monkeypatch.setenv("MAX_REQUEST_BODY_BYTES", "5")
    status_code, body, downstream_called, _ = run_body_middleware(monkeypatch, [b""])
    assert status_code == 200
    assert json.loads(body) == {
        "size": 0,
        "body": "",
        "next_receive": "http.disconnect",
    }
    assert downstream_called


def test_source_validation_error_does_not_echo_submitted_source(monkeypatch):
    marker = "source-secret-marker"
    monkeypatch.setenv("MAX_SOURCE_BYTES", "8")
    response = TestClient(app).post(
        "/api/review",
        json={"filename": "app.py", "code": marker},
    )
    assert response.status_code == 422
    assert marker not in response.text


def test_shared_review_quota_is_enforced(monkeypatch, tmp_path):
    monkeypatch.setenv("SUPABASE_JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))
    monkeypatch.setenv("MAX_REVIEWS_PER_USER_PER_DAY", "1")
    client = TestClient(app)
    request = {"filename": "app.py", "code": "print('x')"}
    assert client.post("/api/v1/reviews", headers=headers("quota-user"), json=request).status_code == 201
    assert client.post("/api/v1/reviews", headers=headers("quota-user"), json=request).status_code == 429


def test_queue_submission_failure_marks_job_failed_without_leaking_error(monkeypatch, tmp_path):
    monkeypatch.setenv("SUPABASE_JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))
    monkeypatch.setattr("app.main.enqueue_job", lambda job_id: (_ for _ in ()).throw(RuntimeError("private source contents")))
    response = TestClient(app).post("/api/v1/reviews", headers=headers("user-a"), json={"filename": "app.py", "code": "print('x')"})
    assert response.status_code == 503
    review = list_reviews("user-a")[0]
    job = get_job("user-a", review.job_id)
    assert review.status == "failed"
    assert job["status"] == "failed"
    assert job["error"] == "Worker dispatch failed (RuntimeError)"
    assert "private source contents" not in job["error"]
    job_response = TestClient(app).get(
        f"/api/v1/jobs/{review.job_id}",
        headers=headers("user-a"),
    )
    assert job_response.json()["error"] == "Analysis failed before completion"


def test_worker_retries_then_reaches_terminal_failure(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))
    monkeypatch.setenv("MAX_JOB_ATTEMPTS", "2")
    init_db()
    review_id, job_id = create_review("user-a", "print('x')", "app.py")
    monkeypatch.setattr(worker, "analyze", lambda lines, language: (_ for _ in ()).throw(RuntimeError("analysis failed")))
    with pytest.raises(RuntimeError, match="analysis failed"):
        worker.run_job(job_id)
    job = get_job("user-a", job_id)
    assert job["status"] == "failed"
    assert job["attempts"] == 2
