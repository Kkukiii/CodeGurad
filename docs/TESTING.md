# Testing and verification

Run these commands from the indicated directories. Use the project virtual environment so scanner and Python versions are explicit.

## Backend

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check app tests scripts
.\.venv\Scripts\python.exe -m compileall -q app scripts
.\.venv\Scripts\python.exe -m pip check
```

## Real scanner executables

Install the pinned tools into the backend environment with `python -m pip install -r scanner-requirements.txt`, then run:

```powershell
cd backend
.\.venv\Scripts\python.exe scripts\verify_scanners.py
```

This command reports executable versions, validates the local Semgrep rules, and scans temporary harmless Python/Java source fixtures. The deliberately vulnerable-looking fixtures are never executed. It checks expected Semgrep/Bandit/Ruff rule IDs on the Python fixture, the local Java rule on the Java fixture, and zero findings for clean fixtures. This real CLI check is separate from adapter unit tests, which often mock executable discovery.

## Frontend

```powershell
cd frontend
npm test -- --run
npm run lint
npm run build
npm audit --omit=dev --audit-level=high
```

## Repository checks

From the repository root:

```powershell
git diff --check
git status --short
```

The automated checks do not contact Supabase, PostgreSQL, an AI provider, or Render. No live migration, JWT/JWKS request, provider inference, deployment, or post-deployment check should be claimed based only on these tests.

The secure API test module includes direct ASGI middleware tests for completed multi-chunk and empty bodies, missing/inaccurate `Content-Length`, oversized bodies, and disconnects before or during a request body. The disconnect tests assert that the downstream application is not invoked and no response is fabricated after the client disconnects.

The authentication tests cover missing configuration as a `503`, standard Supabase JWKS settings derived from `SUPABASE_URL`, rejection of non-HTTPS project URLs and unsupported signing algorithms, valid/expired/invalid token behavior, and readiness. Frontend component tests cover session restoration failure, dashboard loading/success/empty/error states, data-backed summary and findings filters, theme switching, unauthorized-session clearing, and API error presentation. These tests use local fixtures and mocks; they do not verify a live Supabase project.
