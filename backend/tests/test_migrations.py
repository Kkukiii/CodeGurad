from pathlib import Path

import pytest

from app import postgres_storage

MIGRATIONS = Path(__file__).parents[1] / "migrations"


def test_postgres_initial_migration_contains_private_review_schema():
    migration = (MIGRATIONS / "001_initial.sql").read_text(encoding="utf-8")
    for table in ("reviews", "jobs", "findings", "scanner_runs"):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in migration
    assert "owner_id" in migration
    assert "ON DELETE CASCADE" in migration
    assert "content_hash" in migration


class FakeResult:
    def __init__(self, rows=None):
        self.rows = rows or []

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self):
        self.applied = set()
        self.executed_migrations = []
        self.fail_migration = False
        self.rolled_back = False

    def __enter__(self):
        return self

    def __exit__(self, error_type, error, traceback):
        if error_type is not None:
            self.rolled_back = True
        return False

    def execute(self, query, parameters=None):
        if query.startswith("SELECT version FROM schema_migrations"):
            return FakeResult([{"version": version} for version in self.applied])
        if query.startswith("INSERT INTO schema_migrations"):
            self.applied.add(parameters[0])
            return FakeResult()
        if query.startswith("SELECT pg_advisory_xact_lock"):
            return FakeResult()
        if query.startswith("CREATE TABLE IF NOT EXISTS schema_migrations"):
            return FakeResult()
        self.executed_migrations.append(query)
        if self.fail_migration:
            raise RuntimeError("simulated SQL error")
        return FakeResult()


def test_postgres_migration_initial_and_already_applied_are_idempotent(monkeypatch, tmp_path):
    migration_directory = tmp_path / "migrations"
    migration_directory.mkdir()
    migration_file = migration_directory / "001_initial.sql"
    migration_file.write_text("CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY);", encoding="utf-8")
    connection = FakeConnection()
    monkeypatch.setattr(postgres_storage, "MIGRATIONS", migration_directory)
    monkeypatch.setattr(postgres_storage, "connect", lambda: connection)

    postgres_storage.migrate_db()
    postgres_storage.migrate_db()

    assert connection.applied == {"001_initial.sql"}
    assert connection.executed_migrations == ["CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY);"]


def test_postgres_readiness_does_not_apply_pending_migrations(monkeypatch, tmp_path):
    migration_directory = tmp_path / "migrations"
    migration_directory.mkdir()
    (migration_directory / "001_initial.sql").write_text("CREATE TABLE reviews (id TEXT);", encoding="utf-8")
    connection = FakeConnection()
    monkeypatch.setattr(postgres_storage, "MIGRATIONS", migration_directory)
    monkeypatch.setattr(postgres_storage, "connect", lambda: connection)

    with pytest.raises(RuntimeError, match="migrations are pending"):
        postgres_storage.init_db()

    assert not connection.executed_migrations
    assert not connection.applied


def test_postgres_migration_failure_is_rolled_back(monkeypatch, tmp_path):
    migration_directory = tmp_path / "migrations"
    migration_directory.mkdir()
    (migration_directory / "001_initial.sql").write_text("CREATE TABLE broken (id TEXT);", encoding="utf-8")
    connection = FakeConnection()
    connection.fail_migration = True
    monkeypatch.setattr(postgres_storage, "MIGRATIONS", migration_directory)
    monkeypatch.setattr(postgres_storage, "connect", lambda: connection)

    with pytest.raises(RuntimeError, match="simulated SQL error"):
        postgres_storage.migrate_db()

    assert connection.rolled_back
    assert not connection.applied
