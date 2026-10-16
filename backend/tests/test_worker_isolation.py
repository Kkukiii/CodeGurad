import pytest

from app import worker
from app import scanner
from app.storage import create_review, get_job, get_review, init_db


@pytest.fixture(autouse=True)
def disable_external_scanners(monkeypatch):
    monkeypatch.setattr(scanner, "_scanner_executable", lambda name: None)


def test_worker_environment_excludes_application_secrets(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("DATABASE_URL", "worker-database-placeholder")
    monkeypatch.setenv("SUPABASE_JWT_SECRET", "must-not-cross-boundary")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "must-not-cross-boundary")
    monkeypatch.setenv("AI_MAX_INPUT_BYTES", "120000")
    monkeypatch.setenv("AI_MAX_RESPONSE_BYTES", "900000")
    environment = worker._worker_environment()
    assert environment["DATABASE_URL"] == "worker-database-placeholder"
    assert "SUPABASE_JWT_SECRET" not in environment
    assert "ANTHROPIC_API_KEY" not in environment
    assert environment["AI_MAX_INPUT_BYTES"] == "120000"
    assert environment["AI_MAX_RESPONSE_BYTES"] == "900000"
    assert environment["PYTHONNOUSERSITE"] == "1"


def test_production_rejects_inline_worker(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("WORKER_MODE", "inline")
    with pytest.raises(RuntimeError, match="WORKER_MODE=external"):
        worker.enqueue_job("00000000-0000-0000-0000-000000000000")


def test_duplicate_delivery_does_not_duplicate_findings(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))
    init_db()
    review_id, job_id = create_review("owner", "cursor.execute(f'SELECT {user_id}')", "app.py")
    worker.run_job(job_id)
    first = get_review("owner", review_id)
    worker.run_job(job_id)
    second = get_review("owner", review_id)
    assert get_job("owner", job_id)["attempts"] == 1
    assert len(first.findings) == len(second.findings)


def test_finding_ids_are_unique_across_reviews_and_stable_on_retry(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "reviews.sqlite3"))
    init_db()
    review_one, job_one = create_review("owner", "cursor.execute(f'SELECT {user_id}')", "app.py")
    review_two, job_two = create_review("owner", "cursor.execute(f'SELECT {user_id}')", "app.py")
    worker.run_job(job_one)
    first = get_review("owner", review_one)
    worker.run_job(job_two)
    second = get_review("owner", review_two)
    worker.run_job(job_one)
    retried = get_review("owner", review_one)
    assert first.findings and second.findings
    assert {finding.id for finding in first.findings}.isdisjoint({finding.id for finding in second.findings})
    assert [finding.id for finding in first.findings] == [finding.id for finding in retried.findings]
