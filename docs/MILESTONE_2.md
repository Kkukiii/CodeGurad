# Milestone 2

## Delivered locally

- Added user-scoped review/job persistence, JWT authentication, ownership checks, request limits, status polling, deletion, and fail-closed production defaults.
- Added local evidence rules and optional Semgrep, Bandit, and Ruff adapters with explicit coverage/warnings.
- Added an optional OpenAI-compatible provider flow with configured code-analysis, security, remediation, and PR-summary roles.
- Added source-bounded AI evidence, confidence preservation, retrieved-record citation checks, and explicit potential/informational classifications.
- Added lexical retrieval from the bundled synthetic knowledge data. It filters by language, ranks records using source and scanner signals, and returns at most three records.
- Updated the React review UI to distinguish finding classification.
- Updated the Render API build to install the pinned scanner dependencies; deployment remains disabled/not performed.

## Limitations

- The four AI roles are coordinated in one model response, not independently executed agents. No live model/provider configuration was supplied or tested.
- The knowledge data is synthetic and retrieval is lexical, not embedding/vector RAG. It is not authoritative security guidance.
- `confirmed` is a reserved classification; current scanner and AI findings remain potential, while code quality/unsupported-language output is informational.
- No durable queue or isolated worker service exists. The current external worker is a child process of the API. Production review submission remains disabled by default.
- No live Supabase, PostgreSQL, migration, Render, or production checks have been performed.

See [IMPLEMENTATION_STATUS.md](./IMPLEMENTATION_STATUS.md) for the latest local evidence and [DEPLOYMENT.md](./DEPLOYMENT.md) for the external setup still required.
