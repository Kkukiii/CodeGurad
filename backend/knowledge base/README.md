# AI Code Review Security Knowledge Base

## Purpose
Synthetic knowledge base for testing the existing AI Code Review & Security Analysis Agent.

## Dataset
- Records: 180
- Languages: Python and Java
- Includes: vulnerability type, severity, CWE, OWASP mapping, vulnerable code, fixed code, remediation, detection signals, RAG keywords, and test prompts.
- Categories: SQL injection, command injection, hardcoded secrets, path traversal, unsafe deserialization, XSS, weak cryptography, missing authorization, insecure randomness, resource leaks, exception handling, mutable defaults, null dereferences, race conditions, inefficient loops, and input validation.

## Suggested location

```text
sec-view/
├── app/
├── frontend/
├── tests/
└── knowledge_base/
    ├── code_security_knowledge_base.json
    └── code_security_knowledge_base.md
```

## How to use
1. Load the JSON records into the future RAG/knowledge-base layer.
2. Retrieve records using category, language, CWE, OWASP, or keywords.
3. Give retrieved records to the AI security/remediation agent as supporting context.
4. Keep Semgrep, Bandit, and Ruff as deterministic scanners.
5. Validate final AI output with the project's Pydantic schemas.

## Important
This is synthetic testing/knowledge-base data. It is not a replacement for official security rules, verified CVEs, or production security guidance. Placeholder secrets in examples are not real credentials.
