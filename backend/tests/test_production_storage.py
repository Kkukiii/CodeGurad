import pytest

from app import storage


def test_production_without_database_url_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SECURE_REVIEW_DB", str(tmp_path / "must-not-be-used.sqlite3"))
    with pytest.raises(RuntimeError, match="DATABASE_URL is required"):
        storage.init_db()
    assert not (tmp_path / "must-not-be-used.sqlite3").exists()
