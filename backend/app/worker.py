import os
import subprocess
import sys
from pathlib import Path

from .ai import analyze_with_ai
from .ai.knowledge import retrieve_knowledge_for_review
from .analyzer import analyze
from .pipeline import build_coverage, merge_ai_findings, merge_summary
from .scanner import scan_source
from .storage import fail_job, load_job, requeue_job, save_analysis, update_job_running


def _worker_environment() -> dict[str, str]:
    source = os.getenv("WORKER_DATABASE_URL") or os.getenv("DATABASE_URL", "")
    if os.getenv("APP_ENV", "development").lower() == "production" and not os.getenv("WORKER_DATABASE_URL"):
        raise RuntimeError("WORKER_DATABASE_URL is required for production worker dispatch")
    allowed = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(Path(__file__).parents[1]),
        "APP_ENV": os.getenv("APP_ENV", "development"),
        "DATABASE_URL": source,
        "SECURE_REVIEW_DB": os.getenv("SECURE_REVIEW_DB", ""),
        "MAX_JOB_ATTEMPTS": os.getenv("MAX_JOB_ATTEMPTS", "2"),
        "REVIEW_TIMEOUT_SECONDS": os.getenv("REVIEW_TIMEOUT_SECONDS", "60"),
        "MAX_SCANNER_OUTPUT_BYTES": os.getenv("MAX_SCANNER_OUTPUT_BYTES", "1000000"),
        "SEMGREP_RULES_PATH": os.getenv("SEMGREP_RULES_PATH", ""),
        "AI_PROVIDER": os.getenv("AI_PROVIDER", ""),
        "AI_MODEL": os.getenv("AI_MODEL", ""),
        "AI_API_KEY": os.getenv("AI_API_KEY", ""),
        "AI_BASE_URL": os.getenv("AI_BASE_URL", "https://api.openai.com/v1"),
        "AI_CONNECT_TIMEOUT_SECONDS": os.getenv("AI_CONNECT_TIMEOUT_SECONDS", "5"),
        "AI_READ_TIMEOUT_SECONDS": os.getenv("AI_READ_TIMEOUT_SECONDS", "20"),
        "AI_TOTAL_TIMEOUT_SECONDS": os.getenv("AI_TOTAL_TIMEOUT_SECONDS", os.getenv("AI_TIMEOUT_SECONDS", "45")),
        "AI_TIMEOUT_SECONDS": os.getenv("AI_TIMEOUT_SECONDS", "45"),
        "AI_MAX_ATTEMPTS": os.getenv("AI_MAX_ATTEMPTS", "2"),
        "AI_MAX_RETRY_DELAY_SECONDS": os.getenv("AI_MAX_RETRY_DELAY_SECONDS", "1"),
        "AI_MAX_INPUT_BYTES": os.getenv("AI_MAX_INPUT_BYTES", "150000"),
        "AI_MAX_RESPONSE_BYTES": os.getenv("AI_MAX_RESPONSE_BYTES", "1000000"),
        "SEMGREP_SEND_METRICS": "off",
        "PYTHONNOUSERSITE": "1",
        "TEMP": os.getenv("TEMP", ""),
        "TMP": os.getenv("TMP", ""),
    }
    for name in ("SYSTEMROOT", "WINDIR"):
        if os.getenv(name):
            allowed[name] = os.environ[name]
    return allowed


def run_job(job_id: str) -> None:
    job = load_job(job_id)
    if not job:
        raise ValueError("job not found")
    if not update_job_running(job_id):
        return
    try:
        local_findings = analyze(job["source"].splitlines(), job["language"])
        scanner_run = scan_source(job["source"], job["filename"], job["language"])
        from .pipeline import _scanner_finding

        findings = local_findings + [_scanner_finding(item) for item in scanner_run.findings]
        knowledge_outcome = retrieve_knowledge_for_review(
            job["source"], job["language"], findings,
        )
        ai_outcome = analyze_with_ai(
            job["source"],
            job["filename"],
            job["language"],
            findings,
            retrieved_knowledge=knowledge_outcome.records,
            retrieval_status=(
                "unavailable" if knowledge_outcome.status == "skipped_or_failed"
                else "completed" if knowledge_outcome.records else "no_matches"
            ),
        )
        findings = merge_ai_findings(findings, ai_outcome.findings)
        warnings = scanner_run.warnings
        warnings += [warning for warning in (knowledge_outcome.warning, ai_outcome.warning) if warning]
        coverage = build_coverage(
            job["language"], scanner_run.tools, ai_outcome, knowledge_outcome,
        )
        save_analysis(job_id, findings, merge_summary(findings, ai_outcome.summary), scanner_run.tools, coverage, warnings, [{"scanner": name, "status": "completed" if name in scanner_run.tools else "skipped", "findings_count": sum(item.scanner == name for item in scanner_run.findings)} for name in ("semgrep", "bandit", "ruff")])
    except Exception as error:
        latest = load_job(job_id)
        max_attempts = max(1, int(os.getenv("MAX_JOB_ATTEMPTS", "2")))
        if latest and latest["attempts"] < max_attempts:
            requeue_job(job_id)
            run_job(job_id)
            return
        fail_job(job_id, f"Analysis failed ({type(error).__name__})")
        raise


def enqueue_job(job_id: str) -> None:
    mode = os.getenv("WORKER_MODE", "inline").lower()
    if mode == "external":
        subprocess.Popen(
            [sys.executable, "-m", "app.worker_runner", job_id],
            cwd=Path(__file__).parents[1], env=_worker_environment(), shell=False,
            close_fds=True, start_new_session=True,
        )
        return
    if os.getenv("APP_ENV", "development").lower() == "production":
        raise RuntimeError("WORKER_MODE=external is required in production")
    run_job(job_id)
