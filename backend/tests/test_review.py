from fastapi.testclient import TestClient
import pytest

from app import scanner
from app.main import app


client = TestClient(app)


@pytest.fixture(autouse=True)
def disable_external_scanners(monkeypatch):
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

def test_review_rejects_oversized_source():
    response = client.post("/api/review", json={"code": "\n".join(["x = 1"] * 601), "filename": "app.py"})
    assert response.status_code == 413


def test_review_rejects_unsafe_filename():
    response = client.post("/api/review", json={"code": "print('x')", "filename": "../secret.py"})
    assert response.status_code == 422


def test_review_rejects_unsupported_extension():
    response = client.post("/api/review", json={"code": "print('x')", "filename": "script.sh"})
    assert response.status_code == 422


def test_legacy_review_and_chat_routes_are_disabled_in_production(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    assert client.post("/api/review", json={"code": "print('x')", "filename": "app.py"}).status_code == 404
    assert client.get("/api/review/nonexistent").status_code == 404
    assert client.post("/api/chat", json={"review_id": "nonexistent", "message": "why?"}).status_code == 404
