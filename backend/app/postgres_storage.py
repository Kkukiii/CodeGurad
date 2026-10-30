import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from .preprocess import prepare_code
from .schemas import Finding, Review, ReviewSummary, normalize_finding_ids


MIGRATIONS = Path(__file__).parents[1] / "migrations"
MIGRATION_LOCK_ID = 7730846152264042305


def _now() -> datetime:
    return datetime.now(timezone.utc)


def connect():
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as error:
        raise RuntimeError("PostgreSQL backend requires psycopg; install backend requirements") from error
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is not configured")
    timeout = max(1, int(os.getenv("PG_CONNECT_TIMEOUT_SECONDS", "5")))
    return psycopg.connect(database_url, row_factory=dict_row, connect_timeout=timeout)


def _migration_files() -> list[Path]:
    migrations = sorted(MIGRATIONS.glob("*.sql"))
    versions = [migration.name for migration in migrations]
    if len(versions) != len(set(versions)):
        raise RuntimeError("Migration filenames must be unique")
    return migrations


def check_db() -> None:
    with connect() as connection:
        applied = {row["version"] for row in connection.execute("SELECT version FROM schema_migrations").fetchall()}
        pending = [migration.name for migration in _migration_files() if migration.name not in applied]
        if pending:
            raise RuntimeError("Database migrations are pending; run `python -m app.migrate`")


def init_db() -> None:
    check_db()


def migrate_db() -> None:
    migrations = _migration_files()
    with connect() as connection:
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (MIGRATION_LOCK_ID,))
        connection.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())")
        applied = {row["version"] for row in connection.execute("SELECT version FROM schema_migrations").fetchall()}
        for migration in migrations:
            if migration.name in applied:
                continue
            connection.execute(migration.read_text(encoding="utf-8"))
            connection.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (migration.name,))


def create_review(owner_id: str, code: str, filename: str) -> tuple[str, str]:
    prepared = prepare_code(code, filename)
    review_id, job_id = str(uuid4()), str(uuid4())
    with connect() as connection:
        connection.execute("INSERT INTO reviews (id, owner_id, filename, language, source, content_hash, status, job_id, policy_version, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (review_id, owner_id, filename, prepared.language, code, hashlib.sha256(code.encode()).hexdigest(), "queued", job_id, "2026-10-evidence-v1", _now(), _now()))
        connection.execute("INSERT INTO jobs (id, review_id, owner_id, status) VALUES (%s, %s, %s, %s)", (job_id, review_id, owner_id, "queued"))
    return review_id, job_id


def _review_from_row(connection, row: dict[str, Any]) -> Review:
    finding_rows = connection.execute("SELECT payload_json FROM findings WHERE review_id = %s ORDER BY line_start, id", (row["id"],)).fetchall()
    findings = [Finding.model_validate(item["payload_json"]) for item in finding_rows]
    summary = ReviewSummary.model_validate(row["summary_json"]) if row["summary_json"] else ReviewSummary(verdict="approve", counts={}, top_risks=[], roadmap=[], markdown="Review is queued.")
    return Review(id=row["id"], filename=row["filename"], language=row["language"], lines=len(row["source"].splitlines()), findings=findings, summary=summary, status=row["status"], job_id=row["job_id"], tools=row["tools_json"], coverage=row["coverage_json"], warnings=row["warnings_json"], created_at=row["created_at"].isoformat(), updated_at=row["updated_at"].isoformat())


def get_review(owner_id: str, review_id: str) -> Review | None:
    with connect() as connection:
        row = connection.execute("SELECT * FROM reviews WHERE id = %s AND owner_id = %s", (review_id, owner_id)).fetchone()
        return _review_from_row(connection, row) if row else None


def list_reviews(owner_id: str) -> list[Review]:
    with connect() as connection:
        rows = connection.execute("SELECT * FROM reviews WHERE owner_id = %s ORDER BY created_at DESC", (owner_id,)).fetchall()
        return [_review_from_row(connection, row) for row in rows]


def count_recent_reviews(owner_id: str, since: str) -> int:
    with connect() as connection:
        row = connection.execute("SELECT COUNT(*) AS count FROM reviews WHERE owner_id = %s AND created_at >= %s", (owner_id, since)).fetchone()
        return int(row["count"])


def get_job(owner_id: str, job_id: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute("SELECT * FROM jobs WHERE id = %s AND owner_id = %s", (job_id, owner_id)).fetchone()
        return row


def load_job(job_id: str) -> dict[str, Any] | None:
    with connect() as connection:
        return connection.execute("SELECT j.*, r.source, r.filename, r.language FROM jobs j JOIN reviews r ON r.id = j.review_id WHERE j.id = %s", (job_id,)).fetchone()


def update_job_running(job_id: str) -> bool:
    with connect() as connection:
        result = connection.execute("UPDATE jobs SET status = 'running', attempts = attempts + 1, started_at = %s WHERE id = %s AND status = 'queued'", (_now(), job_id))
        if result.rowcount != 1:
            return False
        connection.execute("UPDATE reviews SET status = 'running', updated_at = %s WHERE job_id = %s", (_now(), job_id))
        return True


def requeue_job(job_id: str) -> None:
    with connect() as connection:
        connection.execute("UPDATE jobs SET status = 'queued', error = NULL WHERE id = %s", (job_id,))


def save_analysis(job_id: str, findings: list[Finding], summary: ReviewSummary, tools: list[str], coverage: dict[str, str], warnings: list[str], scanner_runs: list[dict[str, Any]]) -> None:
    with connect() as connection:
        job = connection.execute("SELECT review_id FROM jobs WHERE id = %s", (job_id,)).fetchone()
        if not job:
            raise ValueError("job not found")
        review_id = job["review_id"]
        findings = normalize_finding_ids(review_id, findings)
        connection.execute("DELETE FROM findings WHERE review_id = %s", (review_id,))
        for finding in findings:
            connection.execute("INSERT INTO findings (id, review_id, scanner, rule_id, severity, confidence, line_start, line_end, payload_json) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)", (finding.id, review_id, finding.scanner, finding.rule_id, finding.severity, finding.confidence, finding.line_start, finding.line_end, json.dumps(finding.model_dump(mode="json"))))
        connection.execute("DELETE FROM scanner_runs WHERE review_id = %s", (review_id,))
        for run in scanner_runs:
            connection.execute("INSERT INTO scanner_runs (id, review_id, scanner, status, duration_ms, error, findings_count) VALUES (%s, %s, %s, %s, %s, %s, %s)", (str(uuid4()), review_id, run["scanner"], run["status"], run.get("duration_ms"), run.get("error"), run.get("findings_count", 0)))
        status = "completed-with-warnings" if warnings else "completed"
        connection.execute("UPDATE reviews SET status = %s, tools_json = %s, coverage_json = %s, warnings_json = %s, summary_json = %s, updated_at = %s WHERE id = %s", (status, json.dumps(tools), json.dumps(coverage), json.dumps(warnings), json.dumps(summary.model_dump(mode="json")), _now(), review_id))
        connection.execute("UPDATE jobs SET status = %s, finished_at = %s WHERE id = %s", (status, _now(), job_id))


def fail_job(job_id: str, error: str) -> None:
    with connect() as connection:
        connection.execute("UPDATE jobs SET status = 'failed', error = %s, finished_at = %s WHERE id = %s", (error[:500], _now(), job_id))
        connection.execute("UPDATE reviews SET status = 'failed', warnings_json = %s, updated_at = %s WHERE job_id = %s", (json.dumps(["Analysis failed before completion"]), _now(), job_id))


def delete_review(owner_id: str, review_id: str) -> bool:
    with connect() as connection:
        result = connection.execute("DELETE FROM reviews WHERE id = %s AND owner_id = %s", (review_id, owner_id))
        return result.rowcount == 1
