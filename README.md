# Secure Review

A Python/Java code-review service with a React/Vite client. Submitted source is analyzed as data and is never executed. Deterministic findings are kept distinct from optional, unverified hosted-LLM analysis.

## Documentation

- [Architecture](./docs/ARCHITECTURE.md)
- [API](./docs/API.md)
- [Security analysis](./docs/SECURITY_ANALYSIS.md)
- [Testing and verification](./docs/TESTING.md)
- [Milestone 2](./docs/MILESTONE_2.md)
- [Deployment setup and limitations](./docs/DEPLOYMENT.md)
- [Implementation status and latest evidence](./docs/IMPLEMENTATION_STATUS.md)

## Run locally

```powershell
if ((Split-Path -Leaf (Get-Location).Path) -ne "backend") { Set-Location .\backend }
if (-not (Test-Path .venv)) { py -m venv .venv }
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
# Install scanner tools into this venv when running the scanner adapter.
python -m pip install -r scanner-requirements.txt
$env:APP_ENV = "development"
# In local development, the backend reads only VITE_SUPABASE_URL from root .env.local
# if SUPABASE_URL is not set. You may instead set SUPABASE_URL explicitly.
$env:SUPABASE_JWT_MODE = "jwks"
# Optional: restrict to the project's actual signing algorithm, e.g. RS256 or ES256.
python -m uvicorn app.main:app --reload
```

The backend reads secrets and explicit settings from its process environment. In local development only, if `SUPABASE_URL` is absent, it reads just the public `VITE_SUPABASE_URL` value from the root `.env.local`; it does not load or print the frontend publishable key or any other entry. Production ignores `.env.local` and requires explicit backend configuration. JWKS mode derives the standard Supabase endpoint, issuer, and `authenticated` audience; supported asymmetric algorithms default to ES256 and RS256, and can be restricted with `SUPABASE_JWT_ALLOWED_ALGORITHMS`. Explicit JWKS URL, issuer, and audience overrides are supported. For a legacy HS256 project, set `SUPABASE_JWT_MODE=hs256` and provide that project's `SUPABASE_JWT_SECRET` privately in this process instead. Do not use test tokens or put signing secrets in frontend variables.

Open http://127.0.0.1:8000. API documentation is at http://127.0.0.1:8000/docs. Verify `Invoke-RestMethod http://127.0.0.1:8000/health/ready` returns `ready`; if it returns 503, backend auth or storage configuration is still missing. Local development uses SQLite when `DATABASE_URL` is absent. Production requires PostgreSQL and valid auth configuration.

For PostgreSQL, apply schema changes explicitly before starting the API:

```powershell
cd backend
.\.venv\Scripts\python.exe -m app.migrate
```

PostgreSQL readiness checks that migrations have been applied and does not apply them. SQLite's local schema remains initialized by the application.

For the frontend, create the root local environment file only if one does not already exist, then fill it with your own Supabase project values:

```powershell
if (-not (Test-Path .env.local)) { Copy-Item frontend\.env.example .env.local }
cd frontend
npm ci
npm run dev
```

Vite reads the ignored root `.env.local` because `frontend/vite.config.ts` sets `envDir: ".."`. Only `VITE_SUPABASE_URL`, `VITE_SUPABASE_PUBLISHABLE_KEY`, and `VITE_API_BASE_URL` belong there. Never put a service-role key, JWT signing secret, database URL, worker credential, or LLM key in a `VITE_` variable.

## Workflow and boundaries

- React uses Supabase Auth and sends the current access token to FastAPI `/api/v1` routes.
- The signed-in dashboard overview, recent activity, severity totals, and searchable/filterable findings are derived from the caller's persisted review history. Projects and report exports are not presented because the backend does not currently implement them. Light/dark theme selection is available in the workspace.
- The protected API validates source size, filename, language, user identity, quotas, and review ownership before storing a queued review and job.
- SQLite is the local adapter. `DATABASE_URL` selects PostgreSQL; missing production DB/auth configuration fails closed.
- The worker runs local evidence rules and optional Semgrep, Bandit, Ruff, and hosted-LLM stages. Scanner failure/skips are reported as coverage warnings, not clean results.
- Source code is never run. The scanner process has `shell=False`, a restricted environment, timeout and output bounds, and temporary-file cleanup. Windows has no POSIX CPU/memory/process limits.
- Request throttling is in-process and per API instance; daily review quota is counted from persistent storage. Rate limits are not globally distributed.
- Legacy unauthenticated review/chat routes are available only outside production. Production returns 404 for them; use authenticated `/api/v1` routes.
- Local process separation is not a sandbox. Render currently defines only the API and static frontend; there is no durable external queue or dedicated worker service. Do not enable public uploads until worker identity, filesystem, resource, and network isolation are enforced by the runtime.

## Configuration

- `APP_ENV`: use `development` locally and `production` in deployment.
- `DATABASE_URL`: PostgreSQL URI; optional locally, required in production. Do not use a `psql` command string.
- `SECURE_REVIEW_DB`: optional local SQLite path.
- `SUPABASE_URL`: Supabase project URL for backend JWKS verification. If omitted in local development, the backend reads only `VITE_SUPABASE_URL` from root `.env.local`. If `SUPABASE_JWT_MODE` is omitted and a URL is found, the backend selects JWKS mode and derives the standard endpoint, issuer, and `authenticated` audience. Production requires explicit backend environment configuration and never reads `.env.local`.
- `SUPABASE_JWT_MODE`: `hs256` or `jwks`. HS256 requires `SUPABASE_JWT_SECRET`; JWKS accepts `SUPABASE_URL` or explicit `SUPABASE_JWKS_URL`, `SUPABASE_JWT_ISSUER`, and `SUPABASE_JWT_AUDIENCE`. JWKS allows ES256 and RS256 by default and can be restricted to the project's actual signing algorithm.
- `CORS_ALLOWED_ORIGINS`: comma-separated exact browser origins. The local default allows ports 8000 and 5173; set the deployed frontend origin explicitly.
- `WORKER_MODE`: `inline` for development; production requires `external`.
- `WORKER_DATABASE_URL`: required for production worker dispatch and should be a narrowly privileged credential.
- `PUBLIC_REVIEWS_ENABLED`: production review processing is disabled unless explicitly set to `true`; keep the Render default `false` until worker identity, filesystem, resource, and network isolation are enforced and verified.
- `SEMGREP_RULES_PATH`: optional override; default is repository-relative `backend/scanner-rules`. Semgrep uses only this local ruleset; automatic/network rule discovery is not enabled.
- `AI_PROVIDER`, `AI_MODEL`, `AI_API_KEY`, `AI_BASE_URL`, `AI_CONNECT_TIMEOUT_SECONDS`, `AI_READ_TIMEOUT_SECONDS`, `AI_TOTAL_TIMEOUT_SECONDS`, `AI_MAX_ATTEMPTS`, `AI_MAX_RETRY_DELAY_SECONDS`, `AI_MAX_INPUT_BYTES`, and `AI_MAX_RESPONSE_BYTES`: optional server-only OpenAI-compatible integration. Remote `AI_BASE_URL` endpoints must use HTTPS; HTTP is accepted only for loopback development endpoints. Provider/model/key and bounded settings are passed only to the worker. `AI_TIMEOUT_SECONDS` is a legacy total-timeout fallback. No live inference was verified. Do not set these in frontend configuration.
- `LIVE_VERIFY`, `LIVE_TARGET`, `LIVE_AUTH_URL`, and `LIVE_AUTH_TOKEN`: opt-in staging verifier settings. `LIVE_AUTH_URL` is the FastAPI review-list endpoint, not Supabase Auth.

The Semgrep, Bandit, and Ruff packages are pinned in `backend/scanner-requirements.txt`; the backend venv was verified with Semgrep 1.136.0, Bandit 1.8.6, Ruff 0.12.10, and setuptools 80.10.2. Semgrep emitted an OpenTelemetry `pkg_resources` warning recommending `setuptools<81`, which justifies that compatibility pin. Semgrep 1.136.0 requires `opentelemetry-api~=1.25.0`, so `backend/requirements.txt` caps FastAPI below 0.142, where the FastAPI dependency changes to `opentelemetry-api>=1.44.0`. The scanner adapter resolves executables from the active venv when its `Scripts`/`bin` directory is not on `PATH`. The pytest requirement is `>=9.0.3,<10` to avoid PYSEC-2026-1845, fixed in 9.0.3.

## AI and knowledge data

The optional OpenAI-compatible service validates a strict structured response and labels model findings as potential. The code-analysis, security, remediation, and PR-summary roles are configured in `backend/data/ai_modules.json` and returned in one provider response to avoid multiplying calls. Provider errors and missing configuration are represented as skipped/failed AI coverage; deterministic local/scanner results remain available. Source, filename, scanner findings, and retrieved knowledge are sent as JSON-encoded untrusted context only when the provider is configured. Prompt/response byte limits, connection/read/total timeouts, and bounded retries apply. Lexical retrieval selects up to three same-language records from bundled synthetic knowledge data and validates cited IDs. This is not embedding/vector RAG, and the records are not authoritative security guidance. Mocked provider tests are not live inference; no live provider request was performed. See [architecture](./docs/ARCHITECTURE.md) and [security analysis](./docs/SECURITY_ANALYSIS.md).

## Checks

```powershell
cd backend
python -m pytest -q
python -m compileall -q app scripts
cd ..\frontend
npm test
npm run lint
npm run build
npm audit --omit=dev --audit-level=high
```

## Render preparation

`render.yaml` describes a Python API (`rootDir: backend`, installs both backend and pinned scanner requirements, starts `uvicorn app.main:app --host 0.0.0.0 --port $PORT`, health path `/health/live`) and a static frontend (`npm ci && npm run build`, publish `frontend/dist`). Configure API secrets only on the API service and the three `VITE_` browser settings only on the static service. Set `CORS_ALLOWED_ORIGINS` to the actual static-site origin. Apply PostgreSQL migrations explicitly with `python -m app.migrate` before startup; readiness fails while migrations are pending and does not change the schema.

The current API launches an external-mode worker as a child process and passes a separate worker database URL; the Render manifest does not define a dedicated worker or queue. Production review submissions return 503 unless `PUBLIC_REVIEWS_ENABLED=true`. Keep the default disabled until worker isolation is provided and verified. No service was deployed and no live database, Supabase login, or provider request was performed.

Before deployment: rotate any previously exposed provider credential; configure and test Supabase JWT verification and PostgreSQL on authorized staging; install and run pinned scanners in a restricted worker; add a durable queue and enforce worker OS/network/filesystem limits; configure exact CORS origins and distributed rate limiting; review migrations and retention policy.

After deployment: check `/health/live` and `/health/ready`; verify CORS preflight from the real frontend origin; test missing/invalid and valid auth; create, poll, read, cross-user-deny, and delete a staging review; confirm scanner coverage and worker failure behavior; verify logs contain no credentials or submitted source. No deployment or post-deployment check has been run.
