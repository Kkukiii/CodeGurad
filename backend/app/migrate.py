import sys

from .storage import migrate_db


def main() -> int:
    try:
        migrate_db()
    except Exception as error:
        print(f"Database migration failed ({type(error).__name__})", file=sys.stderr)
        return 1
    print("Database migrations applied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
