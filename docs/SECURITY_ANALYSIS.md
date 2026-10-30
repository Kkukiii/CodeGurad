# Security analysis

## Evidence and interpretation

The service combines deterministic local rules with optional Semgrep, Bandit, Ruff, and hosted AI analysis. Tool coverage is visible in each review. A scanner that is absent, inapplicable, times out, returns invalid output, or exits with an error is not reported as a clean completed scan.

Finding severity expresses reported impact; classification describes verification state:

- `potential` is used for security patterns and AI suggestions. It is not a confirmed vulnerability.
- `informational` is used for code-quality output and unsupported-language notices.
- `confirmed` is an allowed schema value but is not emitted by current code.

Scanner and model confidence values are not statistically calibrated. A model-proposed fix is unverified. Users must review evidence and validate remediation independently.

The Semgrep rules live in `backend/scanner-rules/`. Bandit and Ruff run only for Python. Java currently receives local rules and Semgrep; Bandit/Ruff are `not_applicable`.

## Authentication and authorization

- Production readiness fails when the configured JWT mode is incomplete. HS256 requires a server-side signing secret; JWKS mode requires URL, issuer, and audience configuration.
- JWTs are constrained to configured algorithms and validated with expiration and subject requirements. The frontend receives only publishable Supabase configuration; signing secrets, database URLs, worker credentials, and AI keys are server-side.
- Protected review, job, finding, list, and delete queries include the authenticated owner ID. A cross-user object lookup returns not found.
- Legacy unauthenticated review/chat endpoints are disabled in production.
- Per-process request throttling and persistent daily review quotas are implemented. The request limiter is not distributed across instances.

## Source handling and worker boundaries

- Source is size/encoding/name validated and never executed by the application.
- The ASGI request-body middleware counts actual streamed bytes and rejects above its limit without relying on `Content-Length`; it does not forward the body if the client disconnects before the final body event. The source field has its own UTF-8 byte limit. An application server or reverse proxy must also cap incoming requests because a single ASGI body event can already be large before the middleware rejects it.
- Scanner command execution uses `shell=False`, a restricted environment that excludes API and AI credentials, bounded runtime/output, and temporary-directory cleanup. POSIX timeout termination kills the scanner process group; Windows currently terminates only the direct scanner process. Scanner error messages returned to users are generic and do not echo raw scanner output.
- Validation errors omit input values. API/worker failure responses avoid raw exception text; request logs contain a request ID, method, path, and status, not request bodies.
- The worker persists an exception type rather than arbitrary exception details. The API job endpoint returns a generic failure message.
- Process separation is not a sandbox. Render currently starts the worker as a child of the API service; it has no durable queue or separately isolated worker. Windows does not get the POSIX resource limits configured in the scanner adapter. Keep public reviews disabled until runtime identity, filesystem, network, CPU, memory, process, and queue protections are implemented and verified.

## AI and retrieval

AI is optional. If provider/model/key configuration is missing, AI coverage is reported as `skipped_or_failed`, not as a successful AI review. When configured, source, filename, scanner evidence, and retrieved records are sent to the configured provider; configure this only when that transfer is authorized. Remote provider endpoints must use HTTPS; HTTP is accepted only for loopback development endpoints. Connection/read/total timeouts, response/input bounds, and a maximum of three attempts are enforced. The four roles are one coordinated provider response, not independent agents. Mocked provider tests do not verify live inference.

The knowledge file contains synthetic data. Retrieval ranks same-language records lexically against source and scanner context; it is not vector RAG or authoritative guidance. The AI response must cite retrieved record IDs, use source line ranges, and is assigned exact source text as its evidence. Model findings remain `potential`.

## Known gaps and review checklist

- No live Supabase, PostgreSQL, hosted-provider, or Render environment has been tested.
- PostgreSQL schema changes run only through `python -m app.migrate`; API initialization/readiness checks fail while migrations are pending and do not change schema. Review migration SQL and use a backup/authorized staging database before production startup.
- Source is persisted with the review; no retention/expiry policy is implemented.
- No distributed request limiter, durable queue, isolated worker service, or OS sandbox is provided.
- No overall worker job deadline or stale-running-job supervisor is provided; individual scanner/provider operations have their own time bounds.
- `PUBLIC_REVIEWS_ENABLED` defaults to false in Render and should remain false until worker safety is established.
- Review access, secret rotation, storage retention, CORS origins, database backups, and provider data-processing terms must be configured for the actual deployment.

Run the local checks in [TESTING.md](./TESTING.md). They do not substitute for staging authorization and deployment testing.
