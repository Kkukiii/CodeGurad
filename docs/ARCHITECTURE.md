# Architecture

## Components and request flow

- `frontend/` is a React/Vite client. Supabase Auth restores and refreshes the session; the API client sends the current access token only to protected API routes and clears the local session after an API `401`. The dashboard and finding filters derive their metrics from the caller's persisted review history; there are no synthetic project or report records.
- `backend/app/main.py` validates HTTP requests, authenticates protected routes, applies per-process request throttling, and calls the persistence and worker layers.
- `backend/app/storage.py` is the SQLite adapter for local development. `backend/app/postgres_storage.py` is selected when `DATABASE_URL` is set. Both persist reviews, jobs, findings, and ownership.
- `backend/app/worker.py` loads the queued source, runs analysis, and saves the result. In external mode, the API starts a child process on the same host; this is not a durable queue or isolated worker service.
- `backend/app/analyzer.py` implements deterministic local evidence rules. `backend/app/scanner.py` optionally runs Semgrep, Bandit, and Ruff against temporary source files.
- `backend/app/ai/` contains the optional provider client, the configured role definitions in `backend/data/ai_modules.json`, and lexical retrieval over `backend/knowledge base/ai_modules.json`.

The source is treated as data and is never executed by the application. Review requests have bounded source and request sizes; ASGI middleware counts actual received bytes without trusting `Content-Length`. Incomplete bodies ending in `http.disconnect` are not forwarded to the application. The application server/reverse proxy should independently cap request sizes because an incoming ASGI chunk is already allocated before the application can reject it. Scanner subprocesses use argument arrays, `shell=False`, a reduced environment, a timeout, bounded combined output, and temporary-file cleanup. On POSIX, timeout/output-limit termination targets the scanner's process group; Windows currently terminates only the direct scanner process and has no equivalent CPU, memory, or process limits in this implementation. The worker itself has no overall job deadline or stale-running-job supervisor.

## Analysis and trust boundaries

The pipeline orders local rules, applicable scanners, then optional AI analysis. Each scanner's coverage is recorded as `completed`, `skipped_or_failed`, or `not_applicable`; unavailable or failed tools are not represented as a clean scan. `tools` lists the scanners that ran. A completed scanner can still report findings.

The review findings carry a classification independent of severity:

- `potential`: pattern-, scanner-, or AI-reported issue that needs human verification.
- `informational`: code-quality or unsupported-language information.
- `confirmed`: reserved for a future workflow with explicit verification; no current analyzer emits this classification.

Confidence is a tool/model-reported value, not a calibrated probability. Remediation is advisory and is not applied or tested automatically.

When configured, the AI provider receives the submitted source, filename, local/scanner evidence, and retrieved knowledge records. Four configured roles (code analysis, security, remediation, and PR summary) are coordinated in one provider response, not independent model executions. Source comments, scanner text, and retrieved data are marked as untrusted prompt content.

Knowledge retrieval is language-filtered lexical retrieval: identifiers are tokenized case-insensitively, common stop words are excluded, and records are scored using query frequency, inverse document frequency, and stronger weights for title/category/CWE/OWASP and detection-signal matches. At most three records are returned. This is genuine retrieval, not embedding/vector search. The bundled records are synthetic guidance, not authoritative security references. AI citations are restricted to retrieved record IDs; the service reconstructs evidence from submitted source lines and validates ranges. No hosted provider call has been verified.

## Persistence, ownership, and readiness

Each protected review and job is scoped to the authenticated user. Reads, lists, and deletes include the owner ID in their database query. The migration defines owner indexes and cascades findings/jobs when a review is deleted; it does not define Supabase row-level security policies. JWKS configuration can use `SUPABASE_URL` to derive the standard Supabase endpoint, issuer, and authenticated audience. In local development only, FastAPI reads the public `VITE_SUPABASE_URL` value from root `.env.local` if its own URL is unset; it never loads that file in production or imports its other entries. Missing or invalid JWT configuration remains a server-side readiness/authentication configuration error.

`/health/live` is a liveness check and does not check dependencies. `/health/ready` checks persistence/migration state and validates the configured auth mode; in production it also checks worker mode/database configuration when public reviews are enabled. PostgreSQL schema changes are applied explicitly with `python -m app.migrate`; readiness does not apply migrations and returns unavailable while migrations are pending. The migration runner executes ordered SQL files transactionally under a PostgreSQL advisory lock. Local tests use a fake connection; no live PostgreSQL migration was run.

The API persists the full submitted source for analysis and review history. There is no retention/expiry policy implemented. Deployments must decide storage retention, encryption, backup, access, and deletion policy before accepting real source.
