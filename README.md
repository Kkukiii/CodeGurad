# Secure Review

A small, runnable first milestone for the AI Code Review & Security Analysis Agent plan. It reviews Python and Java source without executing submitted code and reports only findings backed by exact source evidence.

## Run locally

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000. API documentation is at http://127.0.0.1:8000/docs.

The protected Phase 2 API uses `SUPABASE_JWT_SECRET` from `backend/.env.example` for server-side HS256 bearer verification and stores local development data in private SQLite. Create a signed token only through your configured auth provider; never use the test token helper as production authentication.

For Supabase PostgreSQL, set `DATABASE_URL` locally using the project database host shown in `backend/.env.example`. Replace `<URL_ENCODED_PASSWORD>` locally and percent-encode special password characters. Do not commit the completed connection string or paste it into chat.

`DATABASE_URL` must be a PostgreSQL URI because the adapter passes it to `psycopg.connect`; a `psql -h ...` shell command is not a valid value. `LIVE_AUTH_URL` is a FastAPI URL, not a Supabase Auth or REST URL. The verifier sends a bearer-authenticated `GET` to it, so use the deployed API review-list endpoint ending in `/api/v1/reviews`.

The supplied Supabase browser configuration is stored locally in the ignored root `.env.local` as `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY`. No Vite frontend currently exists, so these values are not consumed by the FastAPI backend yet. The publishable key must not be used as a server-side secret.

Run tests from `backend`:

```powershell
pytest
```

Optional static-analysis tools are pinned separately in `backend/scanner-requirements.txt`. Install them only in the restricted scanner worker environment:

```powershell
python -m pip install -r scanner-requirements.txt
```

The API never treats an unavailable scanner as a clean result; it returns coverage state and warnings in the review response.

## Configuration map

- `DATABASE_URL`: read by `backend/app/storage.py` and `backend/app/postgres_storage.py`; optional in development, required in production, and must be a PostgreSQL URI.
- `SECURE_REVIEW_DB`: local SQLite path used only when `DATABASE_URL` is absent outside production.
- `SUPABASE_JWT_MODE`: read by `backend/app/auth.py` and `backend/app/main.py`; `hs256` requires `SUPABASE_JWT_SECRET`, while `jwks` requires `SUPABASE_JWKS_URL`, `SUPABASE_JWT_ISSUER`, and `SUPABASE_JWT_AUDIENCE`.
- `WORKER_MODE`: read by `backend/app/worker.py`; inline is development-only and production requires `external`.
- `WORKER_DATABASE_URL`: separate worker database connection required for production external dispatch.
- `LIVE_VERIFY`, `LIVE_TARGET`, `LIVE_AUTH_URL`, and `LIVE_AUTH_TOKEN`: read only by `backend/scripts/verify_live.py`; live checks require explicit staging opt-in.
- `VITE_SUPABASE_URL`, `VITE_SUPABASE_PUBLISHABLE_KEY`, and `VITE_API_BASE_URL`: read by the Vite frontend; no server secrets belong in these variables.

## Current scope

- FastAPI `POST /api/review` and `GET /api/review/{id}`
- Python and Java language detection, null-byte removal, and 600-line cap
- Evidence-backed checks for SQL injection, hardcoded secrets, SSTI, unsafe deserialization, and broad exception handling
- CWE/OWASP mapping, severity, remediation examples, deduplication, and PR-style verdict
- Lightweight browser portal served by the API
- In-memory review storage for the MVP
- Validated AI-module configuration in `backend/data/ai_modules.json`, exposed as read-only metadata through `GET /api/modules`
- Protected versioned review/job routes under `/api/v1` with owner filtering and persisted local job state

The legacy deterministic endpoint does not require credentials, while the protected Phase 2 API requires `SUPABASE_JWT_SECRET`. Hosted LLM, vector database, streaming, and full frontend integrations remain separate stages. Never place API keys in submitted source or frontend code.

The Phase 2 storage and worker path is for local verification. It is not a production isolation boundary and must be replaced with managed Postgres/private storage plus a restricted worker runtime before public uploads are enabled.

## Worker boundary

For local tests, `WORKER_MODE=inline` runs the worker in-process. Production rejects that mode. Configure `WORKER_MODE=external` and start a separate worker process with:

```powershell
python -m app.worker_runner <queued-job-id>
```

The worker uses a scrubbed environment, private temporary directories, explicit scanner executables, preinstalled Semgrep rules, scanner timeouts, output limits, and POSIX resource limits where supported. A deployment provider must still enforce the worker identity, network egress policy, filesystem permissions, and OS-level resource limits before public uploads are enabled.

## Supplying AI module data

Put approved module configuration in `backend/data/ai_modules.json`. The required shape and security rules are documented in [backend/data/README.md](backend/data/README.md). When you provide the real dataset or JSON, replace the placeholder prompts and keep secrets outside the repository in environment variables.

## Frontend

The React/Vite frontend lives in [frontend](frontend). Run it with `npm install` followed by `npm run dev` from that directory. It uses Supabase Auth in the browser and calls the protected FastAPI `/api/v1` endpoints with the current access token. [render.yaml](render.yaml) now describes a Render Python API service with `/health/live` plus a static frontend service. Configure the API's `CORS_ALLOWED_ORIGINS` with the deployed frontend origin. Deployment, live sign-in, and worker isolation have not been performed.
