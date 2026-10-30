import json
import os
import signal
import shutil
import subprocess
import tempfile
import threading
import time
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScannerFinding:
    scanner: str
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: float
    line_start: int
    line_end: int
    evidence: str
    category: str
    cwe: str | None = None


@dataclass(frozen=True)
class ScannerRun:
    findings: list[ScannerFinding]
    tools: list[str]
    warnings: list[str]


def _severity(value: str | None) -> str:
    normalized = (value or "info").lower()
    return {"error": "high", "warning": "medium", "note": "low"}.get(normalized, normalized if normalized in {"critical", "high", "medium", "low", "info"} else "info")


def parse_semgrep(payload: dict) -> list[ScannerFinding]:
    results = payload.get("results")
    if not isinstance(results, list) or any(not isinstance(result, dict) for result in results):
        raise ValueError("invalid Semgrep result structure")
    findings = []
    for result in results:
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        start = result.get("start", {}).get("line", 1)
        end = result.get("end", {}).get("line", start)
        findings.append(ScannerFinding(
            scanner="semgrep", rule_id=result.get("check_id", "unknown"),
            title=extra.get("message", "Semgrep finding"),
            description=extra.get("message", "Semgrep reported a match."),
            severity=_severity(metadata.get("severity")), confidence=0.85,
            line_start=start, line_end=end, evidence=extra.get("lines", ""),
            category=metadata.get("category", "security"), cwe=(metadata.get("cwe") or [None])[0] if isinstance(metadata.get("cwe"), list) else metadata.get("cwe"),
        ))
    return findings


def parse_bandit(payload: dict) -> list[ScannerFinding]:
    results = payload.get("results")
    if not isinstance(results, list) or any(not isinstance(result, dict) for result in results):
        raise ValueError("invalid Bandit result structure")
    findings = []
    for result in results:
        cwe = result.get("issue_cwe", {}).get("id")
        findings.append(ScannerFinding(
            scanner="bandit", rule_id=result.get("test_id", "unknown"),
            title=result.get("issue_text", "Bandit finding"),
            description=result.get("issue_text", "Bandit reported a match."),
            severity=_severity(result.get("issue_severity")),
            confidence={"high": 0.9, "medium": 0.7, "low": 0.5}.get((result.get("issue_confidence") or "low").lower(), 0.5),
            line_start=result.get("line_number", 1), line_end=result.get("line_number", 1),
            evidence=result.get("code", ""), category="security", cwe=f"CWE-{cwe}" if cwe else None,
        ))
    return findings


def parse_ruff(payload: list[dict]) -> list[ScannerFinding]:
    if not isinstance(payload, list) or any(not isinstance(result, dict) for result in payload):
        raise ValueError("invalid Ruff result structure")
    findings = []
    for result in payload:
        location = result.get("location", {})
        fix = result.get("fix")
        if not isinstance(location, dict) or (fix is not None and not isinstance(fix, dict)):
            raise ValueError("invalid Ruff finding structure")
        start = location.get("row", 1)
        end = location.get("end_row", start)
        findings.append(ScannerFinding(
            scanner="ruff", rule_id=result.get("code", "unknown"),
            title=result.get("message", "Ruff finding"), description=result.get("message", "Ruff reported a match."),
            severity="medium", confidence=0.95, line_start=start, line_end=end,
            evidence=(fix or {}).get("message", ""), category="code_quality",
        ))
    return findings


def _scanner_environment(cwd: Path) -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONNOUSERSITE": "1",
        "HOME": str(cwd),
        "TEMP": str(cwd),
        "TMP": str(cwd),
        "TMPDIR": str(cwd),
        "SEMGREP_SEND_METRICS": "off",
    }
    for name in ("SYSTEMROOT", "WINDIR", "USERPROFILE", "APPDATA", "LOCALAPPDATA"):
        if os.getenv(name):
            environment[name] = os.environ[name]
    return environment


def _resource_limits():
    if os.name == "nt":
        return None
    import resource

    cpu_seconds = max(1, int(os.getenv("SCANNER_CPU_SECONDS", "60")))
    memory_bytes = max(64 * 1024 * 1024, int(os.getenv("SCANNER_MEMORY_BYTES", "536870912")))
    process_limit = max(16, int(os.getenv("SCANNER_PROCESS_LIMIT", "64")))

    def apply_limits():
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        if hasattr(resource, "RLIMIT_NPROC"):
            resource.setrlimit(resource.RLIMIT_NPROC, (process_limit, process_limit))

    return apply_limits


def _scanner_executable(name: str) -> str | None:
    executable = shutil.which(name)
    if executable:
        return executable
    scripts_directory = Path(sys.prefix) / ("Scripts" if os.name == "nt" else "bin")
    candidate = scripts_directory / (f"{name}.exe" if os.name == "nt" else name)
    return str(candidate) if candidate.is_file() else None


def _terminate_process(process: subprocess.Popen) -> None:
    if os.name == "nt":
        process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            process.kill()
    process.wait()


def _run_json(command: list[str], cwd: Path, timeout: int | None = None) -> tuple[dict | list | None, str | None]:
    timeout = timeout or max(1, int(os.getenv("REVIEW_TIMEOUT_SECONDS", "60")))
    max_output = max(1024, int(os.getenv("MAX_SCANNER_OUTPUT_BYTES", "1000000")))
    process = None
    try:
        process = subprocess.Popen(
            command, cwd=cwd, env=_scanner_environment(cwd), shell=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            start_new_session=os.name != "nt", preexec_fn=_resource_limits(),
        )
    except OSError as error:
        return None, f"could not start scanner ({type(error).__name__})"

    stdout = bytearray()
    stderr = bytearray()
    output_size = 0
    output_lock = threading.Lock()
    output_exceeded = threading.Event()

    def capture(stream, buffer: bytearray) -> None:
        nonlocal output_size
        while chunk := stream.read(65536):
            with output_lock:
                available = max_output - output_size
                if len(chunk) > available:
                    output_exceeded.set()
                if available > 0:
                    captured = chunk[:available]
                    buffer.extend(captured)
                    output_size += len(captured)

    readers = [
        threading.Thread(target=capture, args=(process.stdout, stdout), daemon=True),
        threading.Thread(target=capture, args=(process.stderr, stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + timeout
    timed_out = False
    while process.poll() is None:
        if output_exceeded.is_set():
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break
        try:
            process.wait(timeout=min(0.05, remaining))
        except subprocess.TimeoutExpired:
            continue

    if process.poll() is None:
        _terminate_process(process)
    for reader in readers:
        reader.join()

    if output_exceeded.is_set():
        return None, "scanner output exceeded the configured limit"
    if timed_out:
        return None, "timed out"
    stdout_text = stdout.decode("utf-8", errors="replace")
    if process.returncode not in (0, 1):
        return None, f"scanner exited with code {process.returncode}"
    try:
        if not stdout_text.strip():
            return None, "empty scanner output"
        return json.loads(stdout_text), None
    except json.JSONDecodeError:
        return None, "scanner returned invalid JSON"


def _add_scanner_results(name, payload, parser, tools, findings, warnings) -> None:
    try:
        parsed = parser(payload)
    except (AttributeError, KeyError, TypeError, ValueError):
        warnings.append(f"{name} returned malformed JSON; coverage was skipped")
        return
    tools.append(name)
    findings.extend(parsed)


def scan_source(code: str, filename: str, language: str) -> ScannerRun:
    suffix = ".py" if language == "python" else ".java" if language == "java" else ".txt"
    safe_name = Path(filename).name or f"snippet{suffix}"
    findings: list[ScannerFinding] = []
    tools: list[str] = []
    warnings: list[str] = []
    with tempfile.TemporaryDirectory(prefix="secure-review-") as temporary:
        root = Path(temporary)
        source = root / safe_name
        source.write_text(code, encoding="utf-8", errors="strict")
        semgrep_path = _scanner_executable("semgrep")
        semgrep_rules = os.getenv("SEMGREP_RULES_PATH") or str(Path(__file__).parents[1] / "scanner-rules")
        if semgrep_path and semgrep_rules and Path(semgrep_rules).exists():
            payload, error = _run_json([semgrep_path, "--config", semgrep_rules, "--json", "--quiet", safe_name], root)
            if error:
                warnings.append(f"semgrep failed: {error}")
            else:
                _add_scanner_results("semgrep", payload, parse_semgrep, tools, findings, warnings)
        elif not semgrep_path:
            warnings.append("semgrep unavailable; Semgrep coverage was skipped")
        else:
            warnings.append("semgrep rules are not configured; network rule discovery was skipped")
        bandit_path = _scanner_executable("bandit")
        if language == "python" and bandit_path:
            payload, error = _run_json([bandit_path, "-f", "json", "-q", safe_name], root)
            if error:
                warnings.append(f"bandit failed: {error}")
            else:
                _add_scanner_results("bandit", payload, parse_bandit, tools, findings, warnings)
        elif language == "python":
            warnings.append("bandit unavailable; Bandit coverage was skipped")
        ruff_path = _scanner_executable("ruff")
        if language == "python" and ruff_path:
            payload, error = _run_json([ruff_path, "check", "--output-format", "json", safe_name], root)
            if error:
                warnings.append(f"ruff failed: {error}")
            else:
                _add_scanner_results("ruff", payload, parse_ruff, tools, findings, warnings)
        elif language == "python":
            warnings.append("ruff unavailable; Ruff coverage was skipped")
    return ScannerRun(findings=findings, tools=sorted(set(tools)), warnings=warnings)
