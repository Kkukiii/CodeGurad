import json
from typing import ClassVar

import pytest
from fastapi.testclient import TestClient

from app import scanner
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def disable_external_scanners(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setattr(scanner, "_scanner_executable", lambda name: None)


def test_review_reports_evidence_backed_sql_injection():
    response = client.post("/api/review", json={
        "filename": "app.py",
        "code": "user_id = request.args['id']\ncursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
    })
    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["verdict"] == "block"
    assert payload["findings"][0]["cwe"] == "CWE-89"
    assert payload["findings"][0]["line_start"] == 2
    assert "cursor.execute" in payload["findings"][0]["evidence"]


def test_review_distinguishes_potential_security_from_informational_quality():
    response = client.post("/api/review", json={
        "filename": "app.py",
        "code": "cursor.execute(f'SELECT {user_id}')\ntry:\n    pass\nexcept:\n    pass",
    })
    assert response.status_code == 200
    classifications = {finding["category"]: finding["classification"] for finding in response.json()["findings"]}
    assert classifications["A03:2021-Injection"] == "potential"
    assert classifications["code_smell"] == "informational"


def test_review_reports_invalid_ai_configuration_without_claiming_unconfigured(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "openai")
    monkeypatch.delenv("AI_MODEL", raising=False)
    monkeypatch.delenv("AI_API_KEY", raising=False)

    response = client.post("/api/review", json={"filename": "app.py", "code": "value = 1"})

    assert response.status_code == 200
    coverage = response.json()["coverage"]
    assert coverage["ai"] == "skipped_or_failed"
    assert coverage["ai_provider"] == "invalid_configuration"
    assert coverage["ai_model"] == "unavailable"
    assert any("AI_MODEL, AI_API_KEY must be configured" in warning for warning in response.json()["warnings"])
    assert all("unit-test-key" not in warning for warning in response.json()["warnings"])


def test_knowledge_retrieval_runs_and_reports_coverage_without_ai_configuration(monkeypatch):
    for name in ("AI_PROVIDER", "AI_MODEL", "AI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("app.ai.service.configured_provider", lambda: None)

    response = client.post("/api/review", json={
        "filename": "app.py",
        "code": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
    })

    assert response.status_code == 200
    coverage = response.json()["coverage"]
    assert coverage["local_evidence_rules"] == "completed"
    assert coverage["semgrep"] == "skipped_or_failed"
    assert coverage["bandit"] == "skipped_or_failed"
    assert coverage["ruff"] == "skipped_or_failed"
    assert coverage["ai"] == "skipped_or_failed"
    assert coverage["knowledge_retrieval"] == "completed"
    assert int(coverage["knowledge_retrieval_count"]) > 0
    assert coverage["knowledge_retrieval_detail"] == "matched"
    assert coverage["knowledge_retrieval_method"] == "lexical"
    assert coverage["ai_provider_configured"] == "false"
    assert coverage["ai_model_configured"] == "false"
    assert coverage["ai_api_key_configured"] == "false"
    assert any("AI_PROVIDER" in warning for warning in response.json()["warnings"])


def test_coverage_reports_successful_configured_ai_and_missing_knowledge_base(monkeypatch):
    from app.ai.service import AIOutcome
    from app.pipeline import run_review
    from app.scanner import ScannerRun
    from app.schemas import ReviewSummary

    monkeypatch.setenv("AI_PROVIDER", "openai-compatible")
    monkeypatch.setenv("AI_MODEL", "provider/model-id")
    monkeypatch.setenv("AI_API_KEY", "unit-test-key")
    monkeypatch.setattr(
        "app.ai.knowledge.retrieve_knowledge",
        lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError()),
    )
    monkeypatch.setattr(
        "app.pipeline.scan_source",
        lambda *args, **kwargs: ScannerRun([], ["semgrep", "bandit", "ruff"], []),
    )
    monkeypatch.setattr(
        "app.pipeline.analyze_with_ai",
        lambda *args, **kwargs: AIOutcome(
            [], ReviewSummary(verdict="approve", counts={}, top_risks=[], roadmap=[], markdown=""),
            None, status="completed", provider="openai-compatible", model="provider/model-id",
        ),
    )

    review = run_review("value = 1", "app.py")
    coverage = review.coverage

    assert coverage["local_evidence_rules"] == "completed"
    assert coverage["semgrep"] == "completed"
    assert coverage["bandit"] == "completed"
    assert coverage["ruff"] == "completed"
    assert coverage["ai"] == "completed"
    assert coverage["knowledge_retrieval"] == "skipped_or_failed"
    assert coverage["knowledge_retrieval_count"] == "0"
    assert coverage["knowledge_retrieval_detail"] == "knowledge base file is missing"
    assert coverage["ai_provider_configured"] == "true"
    assert coverage["ai_model_configured"] == "true"
    assert coverage["ai_api_key_configured"] == "true"
    assert coverage["ai_provider"] == "openai-compatible"
    assert coverage["ai_model"] == "provider/model-id"
    assert any("knowledge base file is missing" in warning for warning in review.warnings)


def test_end_to_end_coverage_with_mocked_ai_and_lexical_knowledge(monkeypatch):
    from app.ai import provider
    from app.pipeline import run_review
    from app.scanner import ScannerRun

    captured: dict[str, object] = {}
    structured_response = {
        "code_analysis": [],
        "security": [],
        "remediation": [],
        "pr_summary": {
            "verdict": "safe",
            "overall_score": 100,
            "pr_summary": "No additional AI findings.",
            "major_issues": [],
            "security_risk": "No additional AI risks identified.",
            "recommended_actions": [],
        },
    }

    class Response:
        status_code = 200
        headers: ClassVar[dict[str, str]] = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def iter_bytes(self, chunk_size):
            body = {"choices": [{"message": {"content": json.dumps(structured_response)}}]}
            return iter([json.dumps(body).encode()])

    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def stream(self, method, url, *, headers, json, **kwargs):
            captured.update(method=method, url=url, payload=json)
            return Response()

    monkeypatch.setenv("AI_PROVIDER", "openai-compatible")
    monkeypatch.setenv("AI_MODEL", "provider/model-id")
    monkeypatch.setenv("AI_API_KEY", "unit-test-key")
    monkeypatch.setenv("AI_BASE_URL", "https://openrouter.ai/api/v1")
    monkeypatch.setenv("AI_MAX_ATTEMPTS", "1")
    monkeypatch.setattr(provider.httpx, "Client", Client)
    monkeypatch.setattr(
        "app.pipeline.scan_source",
        lambda *args, **kwargs: ScannerRun([], ["semgrep", "bandit", "ruff"], []),
    )

    review = run_review(
        "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        "app.py",
    )
    coverage = review.coverage
    request_payload = captured["payload"]
    assert isinstance(request_payload, dict)
    prompt = request_payload["messages"][1]["content"]

    assert captured["method"] == "POST"
    assert captured["url"] == "https://openrouter.ai/api/v1/chat/completions"
    assert "CWE-89" in prompt
    assert "RETRIEVED_KNOWLEDGE_JSON" in prompt
    assert coverage["local_evidence_rules"] == "completed"
    assert coverage["semgrep"] == "completed"
    assert coverage["bandit"] == "completed"
    assert coverage["ruff"] == "completed"
    assert coverage["ai"] == "completed"
    assert coverage["knowledge_retrieval"] == "completed"
    assert int(coverage["knowledge_retrieval_count"]) > 0
    assert coverage["knowledge_retrieval_detail"] == "matched"
    assert coverage["knowledge_retrieval_method"] == "lexical"
    assert coverage["ai_provider_configured"] == "true"
    assert coverage["ai_model_configured"] == "true"
    assert coverage["ai_api_key_configured"] == "true"


def test_review_rejects_oversized_source():
    response = client.post("/api/review", json={"code": "\n".join(["x = 1"] * 601), "filename": "app.py"})
    assert response.status_code == 413


def test_review_rejects_unsafe_filename():
    response = client.post("/api/review", json={"code": "print('x')", "filename": "../secret.py"})
    assert response.status_code == 422


def test_review_rejects_unsupported_extension():
    response = client.post("/api/review", json={"code": "print('x')", "filename": "script.sh"})
    assert response.status_code == 422


def test_local_chat_explains_the_most_relevant_finding_and_supports_follow_up_questions():
    created = client.post("/api/review", json={
        "filename": "app.py",
        "code": "user_id = request.args['id']\ncursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
    })
    review_id = created.json()["id"]

    supporting = client.post("/api/chat", json={"review_id": review_id, "message": "why is this dangerous?"})
    assert supporting.status_code == 200
    payload = supporting.json()
    assert "SQL query is built with string interpolation" in payload["answer"] or "danger" in payload["answer"].lower()
    assert payload["sources"]

    follow_up = client.post("/api/chat", json={"review_id": review_id, "message": "how do I fix it?"})
    assert follow_up.status_code == 200
    assert "fix" in follow_up.json()["answer"].lower() or "remediation" in follow_up.json()["answer"].lower()
    assert any(source.startswith("knowledge:KB-") for source in follow_up.json()["sources"])


def test_legacy_review_and_chat_routes_are_disabled_in_production(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    assert client.post("/api/review", json={"code": "print('x')", "filename": "app.py"}).status_code == 404
    assert client.get("/api/review/nonexistent").status_code == 404
    assert client.post("/api/chat", json={"review_id": "nonexistent", "message": "why?"}).status_code == 404
