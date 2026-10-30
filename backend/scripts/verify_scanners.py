import os
import subprocess
import sys
import tempfile
from pathlib import Path


BACKEND_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app.scanner import ScannerRun, _scanner_environment, _scanner_executable, scan_source  # noqa: E402


def _run(
    command: list[str],
    timeout: int = 30,
    cwd: Path = BACKEND_ROOT,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=_scanner_environment(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
        shell=False,
    )


def _text(output: bytes) -> str:
    return output.decode("utf-8", errors="replace").strip()


def _report_run(name: str, result: ScannerRun) -> None:
    findings = [(item.scanner, item.rule_id.rsplit(".", 1)[-1], item.line_start) for item in result.findings]
    print(
        f"{name}: tools={','.join(result.tools) or 'none'} "
        f"findings={findings} warnings={len(result.warnings)}"
    )
    for warning in result.warnings:
        print(f"  warning: {warning}")


def main() -> int:
    executables = {
        name: _scanner_executable(name)
        for name in ("semgrep", "bandit", "ruff")
    }
    failed = False

    for name, executable in executables.items():
        if executable is None:
            print(f"{name}: unavailable")
            failed = True
            continue
        version_result = _run([executable, "--version"])
        version_output = _text(version_result.stdout) or _text(version_result.stderr)
        print(f"{name}: {'available' if version_result.returncode == 0 else 'version check failed'} ({version_output[:200]})")
        if version_result.returncode != 0:
            failed = True

    semgrep = executables["semgrep"]
    rules = BACKEND_ROOT / "scanner-rules" / "local.yml"
    if semgrep is None:
        failed = True
    else:
        with tempfile.TemporaryDirectory(prefix="sec-view-semgrep-validate-") as temporary_directory:
            validation = _run(
                [semgrep, "--validate", "--config", str(rules)],
                cwd=Path(temporary_directory),
            )
        validation_output = _text(validation.stdout) or _text(validation.stderr)
        print(f"semgrep rules: exit={validation.returncode} ({validation_output[:300]})")
        failed = failed or validation.returncode != 0

    os.environ["SEMGREP_RULES_PATH"] = str(rules.parent)
    fixtures = {
        "python-vulnerable": (
            "python",
            "fixture.py",
            "user_id = input()\ncursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")\neval(user_id)\ntry:\n    pass\nexcept:\n    pass\n",
        ),
        "python-clean": (
            "python",
            "fixture.py",
            "def add(left, right):\n    return left + right\n",
        ),
        "java-vulnerable": (
            "java",
            "Fixture.java",
            "import java.io.*;\nclass Fixture { Object read(InputStream input) throws Exception { return new ObjectInputStream(input).readObject(); } }\n",
        ),
        "java-clean": (
            "java",
            "Fixture.java",
            "class Fixture { int add(int left, int right) { return left + right; } }\n",
        ),
    }
    results: dict[str, ScannerRun] = {}
    for label, (language, filename, source) in fixtures.items():
        results[label] = scan_source(source, filename, language)
        _report_run(label, results[label])

    vulnerable = results["python-vulnerable"]
    vulnerable_rules = {item.rule_id.rsplit(".", 1)[-1] for item in vulnerable.findings}
    expected_python = {"local-python-sql-interpolation", "B608", "B307", "E722"}
    if not expected_python.issubset(vulnerable_rules):
        print(f"python fixture missing expected checks: {sorted(expected_python - vulnerable_rules)}")
        failed = True
    if results["python-clean"].findings:
        print("python clean fixture unexpectedly produced findings")
        failed = True

    java_rules = {item.rule_id.rsplit(".", 1)[-1] for item in results["java-vulnerable"].findings}
    if "local-java-object-deserialization" not in java_rules:
        print("java fixture did not trigger the local deserialization rule")
        failed = True
    if results["java-clean"].findings:
        print("java clean fixture unexpectedly produced findings")
        failed = True

    for label, result in results.items():
        required = {"semgrep"} if label.startswith("java-") else {"semgrep", "bandit", "ruff"}
        if not required.issubset(result.tools) or result.warnings:
            print(f"{label} did not complete all applicable scanner checks")
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
