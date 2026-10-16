import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from .preprocess import prepare_code
from .schemas import Finding, Review, ReviewSummary, normalize_finding_ids


DEFAULT_DB = Path(__file__).parents[1] / "data" / "reviews.sqlite3"


def _use_postgres() -> bool:
    if os.getenv("APP_ENV", "development").lower() == "production" and not os.getenv("DATABASE_URL"):
        raise RuntimeError("DATABASE_URL is required in production")
    return bool(os.getenv("DATABASE_URL"))


def _postgres():
    from . import postgres_storage

    return postgres_storage


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db_path() -> Path:
    return Path(os.getenv("SECURE_REVIEW_DB", str(DEFAULT_DB)))


def connect() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db() -> None:
    if _use_postgres():
        _postgres().init_db()
        return
    with connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS reviews (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                language TEXT NOT NULL,
                source TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                job_id TEXT,
                policy_version TEXT NOT NULL,
                tools_json TEXT NOT NULL DEFAULT '[]',
                coverage_json TEXT NOT NULL DEFAULT '{}',
                warnings_json TEXT NOT NULL DEFAULT '[]',
                summary_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_reviews_owner_created ON reviews(owner_id, created_at DESC);
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
                owner_id TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_jobs_owner ON jobs(owner_id, created_at DESC);
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
                scanner TEXT NOT NULL,
                rule_id TEXT,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                line_start INTEGER NOT NULL,
                line_end INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_findings_review ON findings(review_id, severity);
            CREATE TABLE IF NOT EXISTS scanner_runs (
                id TEXT PRIMARY KEY,
                review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
                scanner TEXT NOT NULL,
                status TEXT NOT NULL,
                duration_ms INTEGER,
                error TEXT,
                findings_count INTEGER NOT NULL DEFAULT 0
            );
            """
        )


def create_review(owner_id: str, code: str, filename: str) -> tuple[str, str]:
    if _use_postgres():
        return _postgres().create_review(owner_id, code, filename)
    prepared = prepare_code(code, filename)
    review_id, job_id = str(uuid4()), str(uuid4())
    now = _now()
    import hashlib

    with connect() as connection:
        connection.execute(
            "INSERT INTO reviews (id, owner_id, filename, language, source, content_hash, status, job_id, policy_version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (review_id, owner_id, filename, prepared.language, code, hashlib.sha256(code.encode("utf-8")).hexdigest(), "queued", job_id, "2026-10-evidence-v1", now, now),
        )
        connection.execute(
            "INSERT INTO jobs (id, review_id, owner_id, status, created_at) VALUES (?, ?, ?, ?, ?)",
            (job_id, review_id, owner_id, "queued", now),
        )
    return review_id, job_id


def _review_from_row(connection: sqlite3.Connection, row: sqlite3.Row) -> Review:
    finding_rows = connection.execute("SELECT payload_json FROM findings WHERE review_id = ? ORDER BY line_start, id", (row["id"],)).fetchall()
    findings = [Finding.model_validate(json.loads(item["payload_json"])) for item in finding_rows]
    summary = ReviewSummary.model_validate(json.loads(row["summary_json"])) if row["summary_json"] else ReviewSummary(verdict="approve", counts={}, top_risks=[], roadmap=[], markdown="Review is queued.")
    return Review(
        id=row["id"], filename=row["filename"], language=row["language"], lines=len(row["source"].splitlines()),
        findings=findings, summary=summary, status=row["status"], job_id=row["job_id"],
        tools=json.loads(row["tools_json"]), coverage=json.loads(row["coverage_json"]), warnings=json.loads(row["warnings_json"]),
        created_at=row["created_at"], updated_at=row["updated_at"],
    )


def get_review(owner_id: str, review_id: str) -> Review | None:
    if _use_postgres():
        return _postgres().get_review(owner_id, review_id)
    with connect() as connection:
        row = connection.execute("SELECT * FROM reviews WHERE id = ? AND owner_id = ?", (review_id, owner_id)).fetchone()
        return _review_from_row(connection, row) if row else None


def list_reviews(owner_id: str) -> list[Review]:
    if _use_postgres():
        return _postgres().list_reviews(owner_id)
    with connect() as connection:
        rows = connection.execute("SELECT * FROM reviews WHERE owner_id = ? ORDER BY created_at DESC", (owner_id,)).fetchall()
        return [_review_from_row(connection, row) for row in rows]


def count_recent_reviews(owner_id: str, since: str) -> int:
    if _use_postgres():
        return _postgres().count_recent_reviews(owner_id, since)
    with connect() as connection:
        row = connection.execute("SELECT COUNT(*) AS count FROM reviews WHERE owner_id = ? AND created_at >= ?", (owner_id, since)).fetchone()
        return int(row["count"])


def get_job(owner_id: str, job_id: str) -> dict[str, Any] | None:
    if _use_postgres():
        return _postgres().get_job(owner_id, job_id)
    with connect() as connection:
        row = connection.execute("SELECT * FROM jobs WHERE id = ? AND owner_id = ?", (job_id, owner_id)).fetchone()
        return dict(row) if row else None


def load_job(job_id: str) -> dict[str, Any] | None:
    if _use_postgres():
        return _postgres().load_job(job_id)
    with connect() as connection:
        row = connection.execute("SELECT j.*, r.source, r.filename, r.language FROM jobs j JOIN reviews r ON r.id = j.review_id WHERE j.id = ?", (job_id,)).fetchone()
        return dict(row) if row else None


def update_job_running(job_id: str) -> None:
    if _use_postgres():
        return _postgres().update_job_running(job_id)
    now = _now()
    with connect() as connection:
        result = connection.execute("UPDATE jobs SET status = 'running', attempts = attempts + 1, started_at = ? WHERE id = ? AND status = 'queued'", (now, job_id))
        connection.execute("UPDATE reviews SET status = 'running', updated_at = ? WHERE job_id = ?", (now, job_id))
        return result.rowcount == 1


def requeue_job(job_id: str) -> None:
    if _use_postgres():
        _postgres().requeue_job(job_id)
        return
    with connect() as connection:
        connection.execute("UPDATE jobs SET status = 'queued', error = NULL WHERE id = ?", (job_id,))


def save_analysis(job_id: str, findings: list[Finding], summary: ReviewSummary, tools: list[str], coverage: dict[str, str], warnings: list[str], scanner_runs: list[dict[str, Any]]) -> None:
    if _use_postgres():
        _postgres().save_analysis(job_id, findings, summary, tools, coverage, warnings, scanner_runs)
        return
    now = _now()
    with connect() as connection:
        job = connection.execute("SELECT review_id FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if not job:
            raise ValueError("job not found")
        review_id = job["review_id"]
        findings = normalize_finding_ids(review_id, findings)
        connection.execute("DELETE FROM findings WHERE review_id = ?", (review_id,))
        for finding in findings:
            connection.execute(
                "INSERT INTO findings (id, review_id, scanner, rule_id, severity, confidence, line_start, line_end, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (finding.id, review_id, finding.scanner, finding.rule_id, finding.severity, finding.confidence, finding.line_start, finding.line_end, finding.model_dump_json()),
            )
        connection.execute("DELETE FROM scanner_runs WHERE review_id = ?", (review_id,))
        for run in scanner_runs:
            connection.execute("INSERT INTO scanner_runs (id, review_id, scanner, status, duration_ms, error, findings_count) VALUES (?, ?, ?, ?, ?, ?, ?)", (str(uuid4()), review_id, run["scanner"], run["status"], run.get("duration_ms"), run.get("error"), run.get("findings_count", 0)))
        status = "completed-with-warnings" if warnings else "completed"
        connection.execute("UPDATE reviews SET status = ?, tools_json = ?, coverage_json = ?, warnings_json = ?, summary_json = ?, updated_at = ? WHERE id = ?", (status, json.dumps(tools), json.dumps(coverage), json.dumps(warnings), summary.model_dump_json(), now, review_id))
        connection.execute("UPDATE jobs SET status = ?, finished_at = ? WHERE id = ?", (status, now, job_id))


def fail_job(job_id: str, error: str) -> None:
    if _use_postgres():
        _postgres().fail_job(job_id, error)
        return
    now = _now()
    with connect() as connection:
        connection.execute("UPDATE jobs SET status = 'failed', error = ?, finished_at = ? WHERE id = ?", (error[:500], now, job_id))
        connection.execute("UPDATE reviews SET status = 'failed', warnings_json = ?, updated_at = ? WHERE job_id = ?", (json.dumps(["Analysis failed before completion"]), now, job_id))


def delete_review(owner_id: str, review_id: str) -> bool:
    if _use_postgres():
        return _postgres().delete_review(owner_id, review_id)
    with connect() as connection:
        result = connection.execute("DELETE FROM reviews WHERE id = ? AND owner_id = ?", (review_id, owner_id))
        return result.rowcount == 1
