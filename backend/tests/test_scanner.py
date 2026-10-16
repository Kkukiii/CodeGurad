import os
import sys

from app import scanner
from app.scanner import parse_bandit, parse_ruff, parse_semgrep


def test_parse_semgrep_preserves_rule_and_location():
    findings = parse_semgrep({"results": [{
        "check_id": "python.lang.security.audit.eval-detected",
        "start": {"line": 4}, "end": {"line": 4},
        "extra": {"message": "Avoid eval", "lines": "eval(value)", "metadata": {"severity": "ERROR", "cwe": ["CWE-95"]}},
    }]})
    assert findings[0].rule_id.endswith("eval-detected")
    assert findings[0].line_start == 4
    assert findings[0].cwe == "CWE-95"


def test_parse_bandit_normalizes_cwe_and_confidence():
    findings = parse_bandit({"results": [{
        "test_id": "B307", "issue_text": "Use of eval", "issue_severity": "HIGH",
        "issue_confidence": "HIGH", "line_number": 8, "code": "eval(value)",
        "issue_cwe": {"id": 95},
    }]})
    assert findings[0].cwe == "CWE-95"
    assert findings[0].confidence == 0.9


def test_parse_ruff_preserves_rule_and_line():
    findings = parse_ruff([{"code": "E722", "message": "Do not use bare except", "location": {"row": 3, "end_row": 3}}])
    assert findings[0].rule_id == "E722"
    assert findings[0].line_start == 3


def test_parse_ruff_accepts_null_fix_and_missing_optional_fields():
    findings = parse_ruff([{"fix": None}, {}])
    assert len(findings) == 2
    assert findings[0].evidence == ""
    assert findings[1].rule_id == "unknown"


def test_missing_or_failed_scanner_is_reported(monkeypatch, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    monkeypatch.setenv("SEMGREP_RULES_PATH", str(rules))
    monkeypatch.setattr(scanner.shutil, "which", lambda name: name)
    monkeypatch.setattr(scanner, "_run_json", lambda command, cwd: (None, "timed out" if command[0] == "semgrep" else "exit code 2"))
    result = scanner.scan_source("print('x')", "app.py", "python")
    assert any("semgrep failed: timed out" in warning for warning in result.warnings)
    assert any("bandit failed: exit code 2" in warning for warning in result.warnings)


def test_scanner_executable_falls_back_to_active_venv(monkeypatch, tmp_path):
    scripts_directory = tmp_path / ("Scripts" if os.name == "nt" else "bin")
    scripts_directory.mkdir()
    executable = scripts_directory / ("ruff.exe" if os.name == "nt" else "ruff")
    executable.touch()
    monkeypatch.setattr(scanner.shutil, "which", lambda name: None)
    monkeypatch.setattr(scanner.sys, "prefix", str(tmp_path))
    assert scanner._scanner_executable("ruff") == str(executable)


def test_scanner_temp_directory_is_removed(monkeypatch, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    monkeypatch.setenv("SEMGREP_RULES_PATH", str(rules))
    monkeypatch.setattr(scanner.shutil, "which", lambda name: name if name == "semgrep" else None)
    observed = []
    monkeypatch.setattr(scanner, "_run_json", lambda command, cwd: (observed.append(cwd) or (None, "failed")))
    scanner.scan_source("print('x')", "app.py", "python")
    assert observed
    assert not observed[0].exists()


def test_malformed_scanner_json_is_reported_as_skipped(monkeypatch, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    monkeypatch.setenv("SEMGREP_RULES_PATH", str(rules))
    monkeypatch.setattr(scanner.shutil, "which", lambda name: name)
    monkeypatch.setattr(scanner, "_run_json", lambda command, cwd: ({"results": None}, None))
    result = scanner.scan_source("print('x')", "app.py", "python")
    assert not result.tools
    assert len([warning for warning in result.warnings if "malformed JSON" in warning]) == 3


def test_semgrep_targets_only_the_temporary_source_file(monkeypatch, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    monkeypatch.setenv("SEMGREP_RULES_PATH", str(rules))
    monkeypatch.setattr(scanner, "_scanner_executable", lambda name: "semgrep" if name == "semgrep" else None)
    commands = []

    def run(command, cwd):
        commands.append(command)
        return {"results": []}, None

    monkeypatch.setattr(scanner, "_run_json", run)
    result = scanner.scan_source("print('x')", "fixture.py", "python")
    assert commands[0][-1] == "fixture.py"
    assert "--include" not in commands[0]
    assert result.tools == ["semgrep"]


def test_scanner_output_limit_stops_capture(monkeypatch, tmp_path):
    monkeypatch.setenv("MAX_SCANNER_OUTPUT_BYTES", "1024")
    payload, error = scanner._run_json(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 1000000)"],
        tmp_path,
        timeout=5,
    )
    assert payload is None
    assert error == "scanner output exceeded the configured limit"


def test_scanner_timeout_terminates_process(tmp_path):
    payload, error = scanner._run_json(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        tmp_path,
        timeout=0.2,
    )
    assert payload is None
    assert error == "timed out"
