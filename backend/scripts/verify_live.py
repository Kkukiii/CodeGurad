"""Opt-in live PostgreSQL and API verification.

This script never prints credentials, tokens, connection strings, or source.
Run only against a database/project dedicated to verification data.
"""
import os
import urllib.error
import urllib.request
from pathlib import Path
from uuid import uuid4

from app.postgres_storage import connect, create_review, delete_review, get_review


MIGRATIONS = Path(__file__).parents[1] / "migrations"


def main() -> int:
    if os.getenv("LIVE_VERIFY") != "1":
        print("Not run: set LIVE_VERIFY=1 for explicit live verification")
        return 2
    if os.getenv("LIVE_TARGET") != "staging":
        print("Blocked: LIVE_TARGET must be staging")
        return 2
    if not os.getenv("DATABASE_URL"):
        print("Blocked: DATABASE_URL is not configured")
        return 2
    if not os.getenv("LIVE_AUTH_URL") or not os.getenv("LIVE_AUTH_TOKEN"):
        print("Blocked: LIVE_AUTH_URL and LIVE_AUTH_TOKEN are required")
        return 2
    try:
        with connect() as connection:
            connection.execute("SELECT 1")
            applied = {row["version"] for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()}
            expected = {migration.name for migration in MIGRATIONS.glob("*.sql")}
            if not expected.issubset(applied):
                print("Blocked: expected migrations are not all applied")
                return 1
            print(f"Database connectivity: ok ({len(applied)} migration(s) recorded)")
            try:
                with connection.transaction():
                    connection.execute("CREATE TEMP TABLE secure_review_verify_rollback (value INTEGER)")
                    connection.execute("INSERT INTO secure_review_verify_rollback VALUES (1)")
                    raise RuntimeError("rollback probe")
            except RuntimeError as error:
                if str(error) != "rollback probe":
                    raise
            print("Transaction rollback: ok")
        owner = f"live-verify-{uuid4()}"
        review_id, _ = create_review(owner, "print('verification')", "verify.py")
        try:
            retrieved = get_review(owner, review_id)
            cross_user = get_review(f"{owner}-other", review_id)
            print(f"Private review create/retrieve: {'ok' if retrieved and retrieved.id == review_id else 'failed'}")
            print(f"Cross-user isolation: {'ok' if cross_user is None else 'failed'}")
        finally:
            print(f"Private review cleanup: {'ok' if delete_review(owner, review_id) else 'failed'}")
        auth_url = os.getenv("LIVE_AUTH_URL")
        auth_token = os.getenv("LIVE_AUTH_TOKEN")
        request = urllib.request.Request(auth_url, headers={"Authorization": f"Bearer {auth_token}"})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                print(f"Authenticated API check: HTTP {response.status}")
        except urllib.error.HTTPError as error:
            print(f"Authenticated API check: HTTP {error.code}")
        except (OSError, urllib.error.URLError):
            print("Authenticated API check: unavailable")
        return 0
    except Exception:
        print("Live verification failed; details were withheld")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
