# Secure Review

A Python/Java code-review service with a React/Vite client. Submitted source is analyzed as data and is never executed. Deterministic findings are kept distinct from optional, unverified hosted-LLM analysis.

## Run locally

```powershell
if ((Split-Path -Leaf (Get-Location).Path) -ne "backend") { Set-Location .\backend }
if (-not (Test-Path .venv)) { py -m venv .venv }
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
# Install scanner tools into this venv when running the scanner adapter.
python -m pip install -r scanner-requirements.txt
$env:APP_ENV = "development"
# For asymmetric Supabase signing, use your project URL and its actual algorithm.
$projectUrl = "https://<your-project-ref>.supabase.co"
$env:SUPABASE_JWT_MODE = "jwks"
$env:SUPABASE_JWKS_URL = "$projectUrl/auth/v1/.well-known/jwks.json"
$env:SUPABASE_JWT_ISSUER = "$projectUrl/auth/v1"
$env:SUPABASE_JWT_AUDIENCE = "authenticated"
$env:SUPABASE_JWT_ALLOWED_ALGORITHMS = "ES256" # Use RS256 if that is the project's signing algorithm.
python -m uvicorn app.main:app --reload
```

The backend reads settings from its process environment. `.env.example` and the frontend's root `.env.local` are not loaded by FastAPI. The JWKS example is for asymmetric signing only. For a legacy HS256 project, set `SUPABASE_JWT_MODE=hs256` and provide that project's `SUPABASE_JWT_SECRET` privately in this process instead. Do not use test tokens or put signing secrets in frontend variables.

Open http://127.0.0.1:8000. API documentation is at http://127.0.0.1:8000/docs. Verify `Invoke-RestMethod http://127.0.0.1:8000/health/ready` returns `ready`; if it returns 503, backend auth or storage configuration is still missing. Local development uses SQLite when `DATABASE_URL` is absent. Production requires PostgreSQL and valid auth configuration.

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
- `SUPABASE_JWT_MODE`: `hs256` or `jwks`. HS256 requires `SUPABASE_JWT_SECRET`; JWKS requires `SUPABASE_JWKS_URL`, `SUPABASE_JWT_ISSUER`, and `SUPABASE_JWT_AUDIENCE`. JWKS algorithms default to RS256.
- `CORS_ALLOWED_ORIGINS`: comma-separated exact browser origins. The local default allows ports 8000 and 5173; set the deployed frontend origin explicitly.
- `WORKER_MODE`: `inline` for development; production requires `external`.
- `WORKER_DATABASE_URL`: required for production worker dispatch and should be a narrowly privileged credential.
- `PUBLIC_REVIEWS_ENABLED`: production review processing is disabled unless explicitly set to `true`; keep the Render default `false` until worker identity, filesystem, resource, and network isolation are enforced and verified.
- `SEMGREP_RULES_PATH`: optional override; default is repository-relative `backend/scanner-rules`. Semgrep uses only this local ruleset; automatic/network rule discovery is not enabled.
- `AI_PROVIDER`, `AI_MODEL`, `AI_API_KEY`, `AI_BASE_URL`, `AI_TIMEOUT_SECONDS`, `AI_MAX_INPUT_BYTES`, and `AI_MAX_RESPONSE_BYTES`: optional server-only OpenAI-compatible integration. Provider/model/key values are passed only to the worker; the input/response byte limits are included in its allowlisted environment. No live inference was verified. Do not set these in frontend configuration.
- `LIVE_VERIFY`, `LIVE_TARGET`, `LIVE_AUTH_URL`, and `LIVE_AUTH_TOKEN`: opt-in staging verifier settings. `LIVE_AUTH_URL` is the FastAPI review-list endpoint, not Supabase Auth.

The Semgrep, Bandit, and Ruff packages are pinned in `backend/scanner-requirements.txt`; the backend venv was verified with Semgrep 1.136.0, Bandit 1.8.6, Ruff 0.12.10, and setuptools 80.10.2. Semgrep emitted an OpenTelemetry `pkg_resources` warning recommending `setuptools<81`, which justifies that compatibility pin. Semgrep 1.136.0 requires `opentelemetry-api~=1.25.0`, so `backend/requirements.txt` caps FastAPI below 0.142, where the FastAPI dependency changes to `opentelemetry-api>=1.44.0`. The scanner adapter resolves executables from the active venv when its `Scripts`/`bin` directory is not on `PATH`. The pytest requirement is `>=9.0.3,<10` to avoid PYSEC-2026-1845, fixed in 9.0.3.

## AI and knowledge data

The optional OpenAI-compatible service validates structured responses and labels its findings as AI-generated. Source, filename, and scanner findings are passed as JSON-encoded untrusted context; the full prompt, response bytes, and request time are bounded. Real inference, provider configuration, embeddings, retrieval, and RAG citations have not been tested or implemented. `backend/knowledge base/ai_modules.json` is synthetic knowledge-base data and is not wired into retrieval or the module loader. `/api/modules` exposes no system prompts and currently has no compatible module configuration to load.

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

`render.yaml` describes a Python API (`rootDir: backend`, `uvicorn app.main:app --host 0.0.0.0 --port $PORT`, health path `/health/live`) and a static frontend (`npm ci && npm run build`, publish `frontend/dist`). Configure API secrets only on the API service and the three `VITE_` browser settings only on the static service. Set `CORS_ALLOWED_ORIGINS` to the actual static-site origin. Configure PostgreSQL and review/apply migrations deliberately before enabling authenticated traffic.

The current API launches an external-mode worker as a child process and passes a separate worker database URL; the Render manifest does not define a dedicated worker or queue. Production review submissions return 503 unless `PUBLIC_REVIEWS_ENABLED=true`. Keep the default disabled until worker isolation is provided and verified. No service was deployed and no live database, Supabase login, or provider request was performed.

Before deployment: rotate any previously exposed provider credential; configure and test Supabase JWT verification and PostgreSQL on authorized staging; install and run pinned scanners in a restricted worker; add a durable queue and enforce worker OS/network/filesystem limits; configure exact CORS origins and distributed rate limiting; review migrations and retention policy.

After deployment: check `/health/live` and `/health/ready`; verify CORS preflight from the real frontend origin; test missing/invalid and valid auth; create, poll, read, cross-user-deny, and delete a staging review; confirm scanner coverage and worker failure behavior; verify logs contain no credentials or submitted source. No deployment or post-deployment check has been run.
