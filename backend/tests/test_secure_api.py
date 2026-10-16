import base64
import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient

from app import scanner
from app import worker
from app.main import app
from app.storage import create_review, get_job, init_db


TEST_SECRET = "test-only-secret-32-bytes-long!!"


@pytest.fixture(autouse=True)
def isolate_hs256_configuration(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("SUPABASE_JWT_MODE", "hs256")
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


def test_secure_api_requires_authentication(monkeypatch, tmp_path):
    monkeypatch.setenv("SUPABASE_JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))
    client = TestClient(app)
    assert client.get("/api/v1/reviews").status_code == 401
    assert client.get("/api/v1/reviews", headers={"Authorization": "Bearer invalid"}).status_code == 401


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
    assert client.get(f"/api/v1/reviews/{review['id']}", headers=headers("user-b")).status_code == 404
    assert client.get(f"/api/v1/reviews/{review['id']}/findings", headers=headers("user-b")).status_code == 404
    assert client.delete(f"/api/v1/reviews/{review['id']}", headers=headers("user-b")).status_code == 404
    assert client.delete(f"/api/v1/reviews/{review['id']}", headers=headers("user-a")).status_code == 204
    assert client.get(f"/api/v1/reviews/{review['id']}", headers=headers("user-a")).status_code == 404


def test_ready_health_requires_auth_configuration(monkeypatch, tmp_path):
    monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))
    client = TestClient(app)
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code == 503


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


def test_shared_review_quota_is_enforced(monkeypatch, tmp_path):
    monkeypatch.setenv("SUPABASE_JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))
    monkeypatch.setenv("MAX_REVIEWS_PER_USER_PER_DAY", "1")
    client = TestClient(app)
    request = {"filename": "app.py", "code": "print('x')"}
    assert client.post("/api/v1/reviews", headers=headers("quota-user"), json=request).status_code == 201
    assert client.post("/api/v1/reviews", headers=headers("quota-user"), json=request).status_code == 429


def test_queue_submission_failure_leaves_a_queued_job(monkeypatch, tmp_path):
    monkeypatch.setenv("SUPABASE_JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))
    monkeypatch.setattr("app.main.enqueue_job", lambda job_id: (_ for _ in ()).throw(RuntimeError("queue unavailable")))
    response = TestClient(app).post("/api/v1/reviews", headers=headers("user-a"), json={"filename": "app.py", "code": "print('x')"})
    assert response.status_code == 201
    assert response.json()["status"] == "queued"


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
