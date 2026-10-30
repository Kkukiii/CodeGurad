# API

The API is served by FastAPI. Interactive OpenAPI documentation is available at `/docs` when the service is running.

## Health and configuration

| Method and path | Authentication | Behavior |
|---|---|---|
| `GET /health/live` | None | Process liveness only; does not prove dependencies are ready. |
| `GET /health/ready` | None | Checks persistence initialization and auth configuration; checks worker configuration when production reviews are enabled. |
| `GET /api/health` | None | Compatibility health response. |
| `GET /api/modules` | None | Returns enabled module metadata without system prompts. |

## Protected review API

Protected routes require an `Authorization` header containing a bearer access token. JWT validation is configured for HS256 or JWKS and validates expiry, issuer, and audience. JWKS mode can use `SUPABASE_URL` to derive Supabase's standard JWKS endpoint, issuer, and `authenticated` audience. Local development may source only `VITE_SUPABASE_URL` from the root `.env.local` when the backend URL is unset; production requires explicit backend variables and never reads that file. JWKS allows ES256 and RS256 by default and can be restricted with `SUPABASE_JWT_ALLOWED_ALGORITHMS`. Review and job lookups are owner-scoped; another user's review is returned as not found. If `SUPABASE_JWT_MODE` is omitted, a configured project URL selects JWKS mode; otherwise the legacy HS256 mode remains the default. Missing or invalid JWT configuration fails closed with `503`; a JWKS network or malformed-response failure returns `503 Authentication provider is unavailable`, not an invalid-token `401`. The frontend clears its local Supabase session on API `401` responses, while `403` responses preserve the session.

| Method and path | Behavior |
|---|---|
| `POST /api/v1/reviews` | Validate and persist source, create a queued job, and dispatch it. Returns the review representation; worker dispatch failures return `503` and mark the job failed. |
| `GET /api/v1/reviews` | List the caller's reviews. |
| `GET /api/v1/reviews/{review_id}` | Get one of the caller's reviews. |
| `GET /api/v1/reviews/{review_id}/findings` | Get findings for one of the caller's reviews. |
| `DELETE /api/v1/reviews/{review_id}` | Delete the caller's review and dependent data. |
| `GET /api/v1/jobs/{job_id}` | Get the caller's job status and a generic error message for failed jobs. |

Review request JSON:

```json
{
  "filename": "service.py",
  "code": "print('example')"
}
```

Only `.py` and `.java` filenames are accepted. Source is limited by `MAX_SOURCE_BYTES` (default 100,000 UTF-8 bytes). The ASGI middleware counts actual received request-body bytes, including streamed/chunked bodies, and rejects above `MAX_REQUEST_BODY_BYTES` (default 110,000 bytes) before routing. If the client disconnects before the final body event, the middleware returns without invoking the application or sending a fabricated response. The application server or reverse proxy should also enforce a request cap at least as strict, because a single ASGI message may already contain a large chunk before middleware can reject it. Validation responses omit submitted input values. Request IDs are returned in `X-Request-ID`.

Review responses include status, findings, summary, tools, coverage, and warnings. Finding severity is separate from finding classification (`potential`, `informational`, or reserved `confirmed`). Coverage distinguishes completed, skipped/failed, and not-applicable tools and includes AI/provider/model/knowledge statuses. AI summary/findings are optional and appear only when configuration, provider inference, and structured validation succeed; a provider failure does not erase deterministic results.

PostgreSQL schema changes are applied explicitly before API startup using `python -m app.migrate` from `backend`. Readiness checks database connectivity and migration state but does not apply pending migrations. Local SQLite schema setup remains automatic.

## Development compatibility routes

`POST /api/review`, `GET /api/review/{review_id}`, and `POST /api/chat` are unauthenticated in development for compatibility. They are disabled with `404` in production. Do not expose them as production endpoints.

## Status codes

Common API statuses include `201` for accepted review creation, `401` for missing/invalid authentication, `404` for inaccessible or missing owner-scoped resources, `413` for body/source limits, `422` for request validation errors, `429` for request or daily quota limits, and `503` for unavailable persistence/auth/worker configuration. Exact error details are intentionally generic where internal diagnostics could expose secrets or submitted source.
