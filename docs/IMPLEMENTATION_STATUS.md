# Implementation Status

Last verified: 2026-10-16. This status reflects local code and checks only; no production service was contacted.

## Implemented locally

- React/Vite Code Editor and Quick Analyze submit Python/Java source to authenticated `/api/v1/reviews`; history, findings, deletion, error states, and cancellable job polling are implemented.
- FastAPI validates source size, filename and encoding, verifies HS256 or JWKS JWTs, enforces owner filtering, persists SQLite locally or PostgreSQL when `DATABASE_URL` is configured, and records job/findings/scanner coverage.
- Production requires PostgreSQL/auth configuration, disables the legacy unauthenticated in-memory review/chat routes with 404 responses, and rejects review submissions by default unless `PUBLIC_REVIEWS_ENABLED=true`.
- Local evidence rules and Semgrep/Bandit/Ruff adapters exist. Scanner subprocesses use argument arrays, `shell=False`, a scrubbed environment, a timeout, bounded output, and temporary-file cleanup. The adapter resolves executables from the active venv when its `Scripts`/`bin` directory is absent from `PATH`. Semgrep receives the one source filename directly, loads the repository-relative local ruleset, and does not use automatic network discovery.
- Optional OpenAI-compatible analysis validates JSON, receives local/scanner findings as untrusted prompt context, bounds full prompt and response bytes, and has a timeout. AI findings remain labeled separately from scanner evidence.
- Render describes an API service and static frontend only.

## Not implemented or not verified

- The first scanner check used system Python, which lacked the venv `Scripts` directory on `PATH`; all three pinned tools were already installed in `backend/.venv`. The adapter now falls back to `sys.prefix/Scripts` (Windows) or `sys.prefix/bin` (Unix). Real adapter fixture: Semgrep's check ID (ending in `local-python-sql-interpolation`; the CLI prefixes it with the config path) at line 2, Bandit `B608` at line 2 and `B307` at line 4, Ruff `E722` at line 5; all tools ran without warnings. A separate clean fixture ran all three with zero findings and no warnings. Semgrep rules validate with 3 rules. Semgrep 1.136.0's runtime warning recommends `setuptools<81`, verified with installed setuptools 80.10.2. FastAPI 0.142.0+ requires OpenTelemetry API >=1.44 while Semgrep 1.136.0 requires ~=1.25; `backend/requirements.txt` now caps FastAPI below 0.142. `pip-audit` found pytest 8.4.2 vulnerable (PYSEC-2026-1845, fixed in 9.0.3); requirements now require pytest>=9.0.3,<10. With pytest 9.1.1, `pip-audit -r requirements.txt` reported no known vulnerabilities. Semgrep's tomli constraint was restored afterward, and `pip check` passes.
- `backend/knowledge base/ai_modules.json` is synthetic 180-record data, not a compatible module config. It is not consumed by the LLM or a retrieval/embedding pipeline. `load_modules()` looks for `backend/data/ai_modules.json`, which is absent; `/api/modules` therefore returns an empty list.
- No hosted model request, embeddings, RAG retrieval, or AI citations were tested. AI output is not deterministic scanner evidence.
- There is no dedicated worker service or durable queue in `render.yaml`. External mode starts a subprocess on the API instance; this is not an OS sandbox. Windows lacks the POSIX resource limits used on supported Unix systems. Network egress, filesystem, identity, and memory/CPU/process limits need enforcement by the deployment runtime.
- Request throttling is per process/API instance. Daily review quotas use persistent review counts, but the request limiter is not distributed.
- No live Supabase login/JWKS, PostgreSQL connection/migration, Render deployment, staging review, or post-deployment check was performed. No report-export endpoint exists.
- Credential audit found a non-placeholder provider key in the backend environment template. The template assignment was replaced with a placeholder and current tracked/staged scans are clean; the owner must revoke/rotate the exposed key. No matching key-shaped change was found in reachable Git history by the performed pattern search.

## Verification evidence

| Command/check | Result |
|---|---|
| `backend/.venv` `python -m pytest -q` | 48 passed in 1.53s; one Starlette/httpx deprecation warning |
| `backend/.venv` `python -m pytest tests/test_scanner.py -q` | 11 passed, including venv resolution, real timeout termination, bounded output, malformed JSON, cleanup, and Ruff `fix: null` |
| `python -m pytest tests/test_ai.py -q` | 9 passed using mocks; no provider call |
| `python -m pytest tests/test_review.py -q` | 5 passed, including production legacy-route denial |
| `python -m compileall -q app scripts` | Passed |
| Frontend `npm test -- src/App.test.tsx --reporter=verbose` | 5 passed, including polling cancellation |
| Frontend `npm test -- --reporter=verbose` | 12 passed across 4 test files |
| Frontend `npm run lint` | Passed (`tsc --noEmit`) |
| Frontend `npm run build` | Passed; 75 modules transformed |
| `npm audit --omit=dev --audit-level=high` | 0 production vulnerabilities |
| Backend `ruff check app tests` | Passed |
| Backend `pip-audit -r requirements.txt` | No known vulnerabilities after raising pytest to the advisory-fixed range; temporary audit tool removed afterward to restore Semgrep's tomli constraint |
| Real scanner adapter fixture | Semgrep, Bandit, and Ruff all executed; expected rule IDs/locations returned; separate clean fixture produced zero findings with all three tools marked executed |
| Semgrep rules and venv dependencies | Local rules validated (3 rules); `pip check` reports no broken requirements after FastAPI/OpenTelemetry compatibility bound |
| Local Uvicorn smoke on port 8001 | `/health/live` 200; unauthenticated `/api/v1/reviews` 401; CORS preflight from `http://127.0.0.1:5173` 200 with exact allow-origin; temporary server stopped |
| Live database/auth/provider/Render checks | Not run; no authorized staging configuration supplied |

The project-venv pytest run emitted one Starlette/httpx deprecation warning. API/worker unit tests replace scanner executable resolution with a no-scanner result so normal tests remain fast; scanner execution is validated separately with real temporary fixtures. The CI Ruff check and CI runtime-requirements `pip-audit` command were run locally. CI itself was inspected but not executed. Editor diagnostics reported no errors in touched source files.

## Configuration and deployment

- Backend reads process environment directly; `.env.example` is not auto-loaded. The Vite frontend reads root `.env.local` via `envDir: ".."`.
- Backend settings include `APP_ENV`, `PUBLIC_REVIEWS_ENABLED`, `DATABASE_URL`, `SECURE_REVIEW_DB`, `SUPABASE_JWT_MODE`, `SUPABASE_JWT_SECRET` or `SUPABASE_JWKS_URL` plus `SUPABASE_JWT_ISSUER` and `SUPABASE_JWT_AUDIENCE`, `CORS_ALLOWED_ORIGINS`, `WORKER_MODE`, `WORKER_DATABASE_URL`, `SEMGREP_RULES_PATH`, and optional `AI_PROVIDER`, `AI_MODEL`, `AI_API_KEY`, `AI_BASE_URL`, `AI_TIMEOUT_SECONDS`, `AI_MAX_INPUT_BYTES`, `AI_MAX_RESPONSE_BYTES`. AI byte limits are passed to external workers; credentials remain excluded from scanner subprocess environments.
- Frontend variables are `VITE_SUPABASE_URL`, `VITE_SUPABASE_PUBLISHABLE_KEY`, and `VITE_API_BASE_URL`; no backend secret belongs in the frontend build.
- PostgreSQL schema is in `backend/migrations/001_initial.sql`. Live migration state and transaction behavior were not verified. Do not point migrations at production without explicit review and backup.
- Render API health check is `/health/live`; `CORS_ALLOWED_ORIGINS` must match the deployed static-site origin. Configure secrets only on the API service and public Supabase/API settings on the static frontend.
- Before deployment: rotate the exposed provider key; authorize staging credentials; verify JWT mode and PostgreSQL; run pinned scanners in an isolated Linux worker; add a durable queue and runtime isolation; configure distributed rate limits and retention; review migrations.
- After deployment: verify health/readiness, CORS, invalid/valid auth, review create/poll/read/delete and cross-user denial, scanner coverage/failure handling, and sanitized logs. No deployment was attempted.

## Run locally (PowerShell)

Backend terminal (reuses `.venv` if present):

```powershell
if ((Split-Path -Leaf (Get-Location).Path) -ne "backend") { Set-Location .\backend }
if (-not (Test-Path .venv)) { py -m venv .venv }
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -r scanner-requirements.txt
$env:APP_ENV = "development"
# Set this process's JWT/JWKS settings for the project's signing mode before starting.
python -m uvicorn app.main:app --reload
```

Frontend terminal, from the repository root:

```powershell
if (-not (Test-Path .env.local)) { Copy-Item frontend\.env.example .env.local }
cd frontend
npm ci
npm run dev
```
