from pathlib import Path


MIGRATIONS = Path(__file__).parents[1] / "migrations"


def test_postgres_initial_migration_contains_private_review_schema():
    migration = (MIGRATIONS / "001_initial.sql").read_text(encoding="utf-8")
    for table in ("reviews", "jobs", "findings", "scanner_runs"):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in migration
    assert "owner_id" in migration
    assert "ON DELETE CASCADE" in migration
    assert "content_hash" in migration
