# Milestone 2 and Milestone 3

## Milestone 2 — delivered locally

- Added user-scoped review/job persistence, JWT authentication, ownership checks, request limits, status polling, deletion, and fail-closed production defaults.
- Added local evidence rules and optional Semgrep, Bandit, and Ruff adapters with explicit coverage/warnings.
- Added an optional OpenAI-compatible provider flow with configured code-analysis, security, remediation, and PR-summary roles.
- Added source-bounded AI evidence, confidence preservation, retrieved-record citation checks, and explicit potential/informational classifications.
- Added lexical retrieval from the bundled synthetic knowledge data. It filters by language, ranks records using source and scanner signals, and returns at most three records.
- Updated the React review UI to distinguish finding classification.
- Updated the Render API build to install the pinned scanner dependencies; deployment remains disabled/not performed.

## Milestone 3 — contextual local review assistant

- Added a development-only `/api/chat` flow that answers from an existing local review rather than making an external model request.
- Ranks up to three review findings using lexical overlap, severity, and question intent, then uses the selected finding's description, evidence, and remediation where relevant.
- Retrieves up to three language-filtered secure-coding records from the bundled local knowledge base and incorporates relevant guidance into answers.
- Returns source references for finding IDs, rule IDs, remediation references, and retrieved knowledge records. Retrieval failures are reported in the answer rather than replaced with fabricated guidance.
- Retains a small in-memory follow-up history per review. This history is process-local and is not durable or shared across workers.
- Keeps the legacy review and chat routes unavailable in production. The assistant is not an authenticated chat feature in the signed-in dashboard.

Focused automated coverage includes `test_local_chat_explains_the_most_relevant_finding_and_supports_follow_up_questions`, knowledge relevance and missing/empty-base tests in `backend/tests/test_ai.py`, and `test_legacy_review_and_chat_routes_are_disabled_in_production`. Provider HTTP tests use mocks; no external inference or live service is implied.

## Limitations

- The four AI roles are coordinated in one model response, not independently executed agents. No live model/provider configuration was supplied or tested.
- The knowledge data is synthetic and retrieval is lexical, not embedding/vector RAG. It is not authoritative security guidance.
- `confirmed` is a reserved classification; current scanner and AI findings remain potential, while code quality/unsupported-language output is informational.
- No durable queue or isolated worker service exists. The current external worker is a child process of the API. Production review submission remains disabled by default.
- No live Supabase, PostgreSQL, migration, Render, or production checks have been performed.

See [IMPLEMENTATION_STATUS.md](./IMPLEMENTATION_STATUS.md) for the latest local evidence and [DEPLOYMENT.md](./DEPLOYMENT.md) for the external setup still required.
