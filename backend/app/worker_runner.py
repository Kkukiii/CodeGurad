import re
import sys

from .worker import run_job


_JOB_ID = re.compile(r"^[0-9a-fA-F-]{36}$")


def main(argv: list[str] | None = None) -> int:
    arguments = argv if argv is not None else sys.argv[1:]
    if len(arguments) != 1 or not _JOB_ID.fullmatch(arguments[0]):
        print("invalid worker job identifier")
        return 2
    run_job(arguments[0])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
