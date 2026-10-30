# Implementation status

This report covers local repository code and checks only. No commit, push, deployment, paid service, or external infrastructure change was performed.

## Implemented

- Protected API requests use fail-closed HS256/JWKS authentication and owner-scoped review/job access. JWKS mode derives the standard endpoint, issuer, and authenticated audience from backend `SUPABASE_URL` when explicit values are not provided; readiness and token verification use the same validated configuration. An invalid/non-HTTPS Supabase URL or unsupported JWKS algorithm remains a server-side configuration error. Frontend `VITE_` variables do not configure FastAPI.
- For local development only, if `SUPABASE_URL` is unset, backend auth reads only `VITE_SUPABASE_URL` from the root `.env.local`; production does not read that file. JWKS defaults to trusted asymmetric ES256/RS256 algorithms, and operators can further restrict the allowlist. JWKS transport failures return a distinct provider-unavailable `503` rather than claiming configuration is missing.
- The signed-in frontend includes an account-scoped overview, review history, searchable severity-filtered findings, profile/logout controls, and a light/dark theme toggle. Counts are derived from persisted API results; load failures expose retry instead of presenting fabricated zero metrics. Projects and report exports are omitted because no such backend features exist.
- The request middleware counts actual ASGI body bytes, including streamed/chunked requests, and rejects oversized requests before routing. Source size is independently limited.
- An `http.disconnect` before the final body event causes middleware to return without invoking the application or synthesizing a response for the disconnected peer.
- PostgreSQL migrations run through `python -m app.migrate`, in filename order, transactionally under an advisory lock. PostgreSQL readiness checks applied migration state and does not change schema. Local SQLite schema initialization remains automatic.
- Source is treated as data, not executed. Scanner subprocesses use argument arrays, `shell=False`, a reduced allowlisted environment, timeouts, output bounds, and temporary-file cleanup. POSIX timeout termination kills the scanner process group; Windows terminates only the direct scanner process and has no equivalent CPU/memory/process limits here.
- Local evidence rules and optional Semgrep, Bandit, and Ruff analysis preserve tool coverage and warnings instead of reporting unavailable tools as clean.
- Four AI roles (code analysis, security, remediation, PR summary) are coordinated in one structured provider response. Strict schemas, bounded input/output and timeouts, bounded retries, sanitized errors, HTTPS for remote endpoints (loopback HTTP only), source-line evidence validation, and retrieved-record ID validation are implemented. Deterministic findings remain available when AI is unconfigured or fails.
- AI and scanner provenance is retained when matching same-line/same-evidence observations are merged. AI findings remain potential, with no claim of confirmation or exploit verification.
- Knowledge retrieval is language-filtered lexical ranking over the bundled synthetic knowledge data. It considers source and scanner context and returns up to three records. This is not vector/embedding retrieval or authoritative security guidance.
- PostgreSQL deployment instructions, request/proxy limits, AI limitations, security boundaries, testing steps, API behavior, and implementation evidence are documented in the README and `docs/`.
- Render configuration describes only an API web service and static frontend. `PUBLIC_REVIEWS_ENABLED` remains false; no durable queue or isolated worker service is provided.

## Verification completed locally

| Check | Result |
|---|---|
| Full backend suite (`pytest -p no:cacheprovider -q`) | 100 passed; one Starlette/httpx deprecation warning |
| Focused authentication configuration/JWKS regressions | Included in full suite; covers missing config, derived Supabase JWKS settings, insecure project URL, unsupported algorithm, token validation, and readiness |
| Ruff (`ruff check app tests scripts`) | Passed |
| Python compilation (`compileall -q app tests scripts`) | Passed |
| Backend package consistency (`pip check`) | No broken requirements |
| Python vulnerability audit | Not run: `pip-audit` is not installed; `pip check` verifies dependency consistency, not known vulnerabilities |
| Frontend tests (`npm test -- --run`) | 22 passed across 4 test files |
| Frontend lint (`tsc --noEmit`) | Passed |
| Frontend production build (`npm run build`) | Passed; Vite transformed 75 modules |
| Frontend production dependency audit | Previously returned 0 vulnerabilities with `npm audit --omit=dev --audit-level=high`; not rerun in this audit because it contacts the package registry |
| Real scanner executable verification | Passed with Semgrep 1.136.0, Bandit 1.8.6, Ruff 0.12.10 |
| Local Semgrep rules validation | Exit code 0; 3 local rules |
| Real Python vulnerable-looking fixture | Semgrep `local-python-sql-interpolation` line 2; Bandit B608 line 2, B307 line 3, B110 line 6; Ruff F821 line 2 and E722 line 6 |
| Real clean Python fixture | All three tools executed; no findings or scanner warnings |
| Real Java vulnerable-looking fixture | Semgrep `local-java-object-deserialization` line 2 |
| Real clean Java fixture | Semgrep executed; no findings or scanner warnings |
| Migration runner unit tests | Initial migration, repeat run, readiness not applying pending migrations, and rollback failure path covered with fake connections |
| `git diff --check` | Passed |

Scanner fixture results are real local executable runs and are separate from mocked adapter/provider tests. Semgrep rule validation emitted an ignored trust-anchor notice and a `pkg_resources` deprecation warning; validation still succeeded. Fixture scans emitted zero adapter warnings. No fixture was executed.

The provider, migration, ownership, and worker behavior tests use local test doubles or SQLite; they are not live service verification. Mocked provider tests are not live AI inference.

## Unverified integrations and remaining risks

- No AI provider/model/key is configured in the process environment, so no provider request was made. Do not copy secrets into chat. Configure the documented server-only values locally if authorized.
- No live Supabase/JWKS, PostgreSQL, Render, or staging verification was performed. Fake migration connections do not validate PostgreSQL server behavior. The API process must still receive the actual `SUPABASE_URL` and signing algorithm configuration.
- `render.yaml` has no PostgreSQL service, durable queue, or dedicated worker. External worker mode launches a child process on the API host; this is not a hardened sandbox or durable queue. Windows does not get the configured POSIX scanner resource limits. Keep public reviews disabled.
- Application-level body limiting should be paired with an ASGI server/reverse-proxy cap so oversized chunks are rejected before reaching application memory.
- Submitted source is persisted with the review; no retention/expiry policy exists. Request throttling is per API instance rather than distributed.
- The synthetic knowledge records can be incomplete or incorrect and are not security authorities. Retrieval is lexical and limited to the current review context.
- No complete worker-level deadline or durable recovery supervisor is implemented; scanner subprocess and AI provider timeouts are bounded individually, but the child worker runs on the API host and can leave jobs running if it is terminated or stalls outside those bounded calls.

## Configuration and artifact audit

- Backend settings are read from process environment; `.env.example` is documentation only. The frontend uses public `VITE_` settings. `.env.local` was not opened or modified.
- The backend example environment contains placeholders only. Rotate any provider credential that was real or exposed in an earlier local copy; no credential values are included here.
- Scanner verification uses temporary fixtures and removes them. No commit, push, deploy, external database migration, or external service configuration was performed.
