# Deployment preparation

No deployment has been performed. This document describes the existing `render.yaml` and the external configuration still required; it is not evidence that these services have been created or tested.

## Render services in the repository

`render.yaml` defines:

1. A Python web service rooted at `backend`. Its build installs `requirements.txt` and `scanner-requirements.txt`; it starts `uvicorn app.main:app` and uses `/health/live` as its liveness path.
2. A static frontend that runs `npm ci && npm run build` and publishes `frontend/dist`.

It does not define a PostgreSQL service, durable queue, or dedicated worker service. The configured API worker mode starts a child process on the API host. The manifest's `WORKER_DATABASE_URL` is a required secret placeholder when reviews are enabled, not proof that a queue or worker service exists.

## Required external setup

Before creating services or enabling reviews:

1. Create/authorize a PostgreSQL database and review `backend/migrations/001_initial.sql`. After setting `DATABASE_URL` in the protected API/deployment environment, run `cd backend; python -m app.migrate` as an explicit release step. It applies ordered migrations transactionally under an advisory lock. API readiness checks fail while migrations are pending and do not apply schema changes. The migration runner has fake-connection unit tests; no live PostgreSQL test was performed.
2. Configure the Supabase project URL and publishable key on the frontend. Separately set `SUPABASE_URL` on the API for JWKS verification; the backend derives the standard JWKS endpoint, issuer, and `authenticated` audience from it. Set `SUPABASE_JWT_ALLOWED_ALGORITHMS` to the project's actual signing algorithm. Alternatively, configure the explicit JWKS URL, issuer, and audience overrides, or use legacy HS256 with its signing secret held only by the API.
3. Configure exact `CORS_ALLOWED_ORIGINS`, `DATABASE_URL`, and required auth variables on the API. Configure only `VITE_SUPABASE_URL`, `VITE_SUPABASE_PUBLISHABLE_KEY`, and `VITE_API_BASE_URL` on the static frontend. Vite-prefixed variables do not configure FastAPI.
4. Decide whether submitted code may be sent to a configured AI provider. If authorized, set provider/model/key/base URL and bounded timeout/input/response settings only on the backend. No provider request has been tested.
5. Replace the current child-process arrangement with a durable queue and separately isolated worker, and enforce least-privilege identity, outbound network rules, filesystem restrictions, CPU/memory/process limits, an overall job deadline, stale-running-job recovery, and worker lifecycle/retry monitoring. Configure per-instance secrets for the worker as needed.
6. Keep `PUBLIC_REVIEWS_ENABLED=false` until queue durability and worker isolation are implemented and validated. Production readiness checks worker mode and database configuration when reviews are explicitly enabled; they do not prove a separate worker or sandbox exists.
7. Set the static frontend's API URL and the API's exact deployed CORS origin. Confirm that no backend secret is included in the static build.

## Exact authorized staging checks

Run these only in an authorized staging account, with credentials supplied by the secret manager or local protected shell (never paste them in chat or commit them):

```powershell
# On the API host or a secure deployment shell after configuring DATABASE_URL:
cd backend
python -m app.migrate
python -m uvicorn app.main:app --host 0.0.0.0 --port $env:PORT

# From a protected operator shell; use the actual API URL and browser origin:
Invoke-RestMethod https://<api-host>/health/live
Invoke-RestMethod https://<api-host>/health/ready
curl.exe -i -X OPTIONS https://<api-host>/api/v1/reviews -H "Origin: https://<frontend-host>" -H "Access-Control-Request-Method: POST" -H "Access-Control-Request-Headers: authorization,content-type"
```

Then verify an authorized JWT can list/create/read/delete only its own staging reviews and jobs, while a second authorized identity receives 404 for the first identity's review/findings/job and delete. Verify invalid/missing tokens fail, provider behavior only if AI transfer is explicitly authorized, and worker timeout/failure handling using harmless source. Confirm pending migrations make readiness return 503, successful explicit migrations make it pass, and logs contain neither tokens nor source. These steps have not been run here. The current Render manifest has no PostgreSQL, durable queue, or dedicated isolated worker, so public review submissions should remain disabled.

## Staging acceptance checks

Only after authorization and configuration, verify liveness/readiness, real JWT validation, CORS, review create/poll/read/delete, cross-user denial, scanner coverage and failure handling, migration behavior, worker retries/restarts, data deletion/retention, and sanitized logs. No staging, migration, authentication, provider, or deployment check has been run in this task.
