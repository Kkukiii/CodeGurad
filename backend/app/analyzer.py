import re
from hashlib import sha256

from .schemas import Finding, FindingClassification, Fix


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _finding_id(title: str, line: int) -> str:
    return sha256(f"{title}:{line}".encode()).hexdigest()[:12]


def _finding(
    *, agent: str, category: str, cwe: str | None, owasp_id: str | None,
    severity: str, line: int, title: str, description: str, evidence: str,
    fix: Fix, classification: FindingClassification = "potential",
) -> Finding:
    return Finding(
        id=_finding_id(title, line), agent=agent, classification=classification,
        provenance=["local_rules"],
        category=category, cwe=cwe,
        owasp_id=owasp_id, severity=severity, line_start=line, line_end=line,
        title=title, description=description, evidence=evidence, confidence=0.98,
        fix=fix,
    )


def analyze(lines: list[str], language: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(lines, 1):
        stripped = line.strip()
        if re.search(r"(execute|executemany|executequery)\s*\([^\n]*(f['\"]|%\s|\+\s*\w|\.format\()", line, re.I):
            findings.append(_finding(
                agent="security", category="A03:2021-Injection", cwe="CWE-89",
                owasp_id="A03:2021", severity="critical", line=line_number,
                title="SQL query is built with string interpolation",
                description="User-controlled data can change the structure of this SQL statement. Use a parameterized query and pass values separately.",
                evidence=stripped,
                fix=Fix(explanation="Bind values through the database driver's parameter API so input remains data.", corrected_code="# Replace string-built SQL with: cursor.execute(\"SELECT ... WHERE id = ?\", (user_id,))", references=["OWASP SQL Injection Prevention Cheat Sheet"]),
            ))
        if re.search(r"(password|secret|api[_-]?key|token)\s*=\s*['\"][^'\"]{6,}['\"]", line, re.I):
            findings.append(_finding(
                agent="security", category="A07:2021-Identification and Authentication Failures", cwe="CWE-798",
                owasp_id="A07:2021", severity="high", line=line_number,
                title="Hardcoded secret detected",
                description="A credential-like value is embedded in source code and may be exposed through version control or artifacts.",
                evidence=stripped,
                fix=Fix(explanation="Load the value from a secret manager or environment variable and rotate the exposed credential.", corrected_code="secret = os.environ[\"APP_SECRET\"]", references=["OWASP Secrets Management Cheat Sheet"]),
            ))
        if re.search(r"render_template_string\s*\(|jinja2\.Template\s*\(", line):
            findings.append(_finding(
                agent="security", category="A03:2021-Injection", cwe="CWE-94",
                owasp_id="A03:2021", severity="high", line=line_number,
                title="Template is constructed from dynamic input",
                description="Rendering attacker-controlled template text can enable server-side template injection.",
                evidence=stripped,
                fix=Fix(explanation="Use a fixed template file and pass untrusted values as escaped context data.", corrected_code="return render_template(\"page.html\", name=user_name)", references=["OWASP Server-Side Request Forgery Prevention Cheat Sheet"]),
            ))
        if re.search(r"pickle\.loads?\s*\(|ObjectInputStream", line):
            findings.append(_finding(
                agent="security", category="A08:2021-Software and Data Integrity Failures", cwe="CWE-502",
                owasp_id="A08:2021", severity="critical", line=line_number,
                title="Untrusted data is deserialized",
                description="Native object deserialization can execute attacker-controlled behavior. Prefer a constrained data format such as JSON.",
                evidence=stripped,
                fix=Fix(explanation="Replace native object deserialization with schema-validated JSON and reject unexpected fields.", corrected_code="payload = json.loads(request.data)", references=["OWASP Deserialization Cheat Sheet"]),
            ))
        if re.search(r"except\s*:\s*$", stripped) or re.search(r"except Exception:\s*$", stripped):
            findings.append(_finding(
                agent="code_analysis", category="code_smell", cwe=None,
                owasp_id=None, severity="medium", line=line_number,
                title="Broad exception handler may hide failures",
                description="Catching every exception without narrowing the type or recording context can conceal defects and security-relevant failures.",
                evidence=stripped,
                fix=Fix(explanation="Catch the expected exception types, log useful context, and preserve the failure contract.", corrected_code="except ValueError as error:\n    logger.warning(\"Invalid input: %s\", error)", references=["Python Exception Handling Guidelines"]),
                classification="informational",
            ))
    if language == "unknown" and lines:
        findings.append(_finding(
            agent="code_analysis", category="unsupported_language", cwe=None,
            owasp_id=None, severity="info", line=1,
            title="Language could not be determined",
            description="Use a .py or .java filename so language-specific checks can be applied.",
            evidence=lines[0].strip(),
            fix=Fix(explanation="Submit Python or Java source with its file extension.", corrected_code=lines[0], references=[]),
            classification="informational",
        ))
    return dedupe(findings)


def dedupe(findings: list[Finding]) -> list[Finding]:
    unique: dict[tuple[str | None, int, str], Finding] = {}
    for finding in findings:
        key = (finding.cwe, finding.line_start, finding.title)
        existing = unique.get(key)
        if existing is None or SEVERITY_RANK[finding.severity] > SEVERITY_RANK[existing.severity]:
            unique[key] = finding
    return list(unique.values())
