from collections import Counter
from hashlib import sha256
from uuid import uuid4

from .analyzer import analyze
from .ai import analyze_with_ai
from .preprocess import prepare_code
from .scanner import ScannerFinding, scan_source
from .schemas import Review, ReviewSummary, normalize_finding_ids
from .schemas import Finding, Fix


REVIEWS: dict[str, Review] = {}


def _scanner_finding(item: ScannerFinding):
    finding_id = sha256(f"{item.scanner}:{item.rule_id}:{item.line_start}".encode()).hexdigest()[:12]
    return Finding(
        id=finding_id,
        agent="security" if item.category == "security" else "code_analysis",
        classification="informational" if item.category == "code_quality" else "potential",
        provenance=[item.scanner],
        category=item.category,
        cwe=item.cwe,
        severity=item.severity,
        line_start=item.line_start,
        line_end=item.line_end,
        title=item.title,
        description=item.description,
        evidence=item.evidence,
        confidence=item.confidence,
        scanner=item.scanner,
        rule_id=item.rule_id,
    )


def merge_ai_findings(findings: list[Finding], ai_findings: list[Finding]) -> list[Finding]:
    merged = list(findings)
    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for ai_finding in ai_findings:
        duplicate = next(
            (
                index for index, finding in enumerate(merged)
                if finding.agent == ai_finding.agent
                and finding.line_start == ai_finding.line_start
                and finding.line_end == ai_finding.line_end
                and finding.evidence == ai_finding.evidence
                and "ai" not in finding.provenance
            ),
            None,
        )
        if duplicate is None:
            merged.append(ai_finding)
            continue

        original = merged[duplicate]
        descriptions = [original.description]
        if ai_finding.description not in original.description:
            descriptions.append(f"AI observation: {ai_finding.description}")
        if original.fix and ai_finding.fix:
            fix = Fix(
                explanation=f"{original.fix.explanation}\nAI suggestion: {ai_finding.fix.explanation}",
                corrected_code=original.fix.corrected_code or ai_finding.fix.corrected_code,
                references=list(dict.fromkeys(original.fix.references + ai_finding.fix.references)),
                verified=original.fix.verified and ai_finding.fix.verified,
            )
        else:
            fix = original.fix or ai_finding.fix
        merged[duplicate] = original.model_copy(update={
            "description": " ".join(descriptions),
            "fix": fix,
            "provenance": list(dict.fromkeys(original.provenance + ai_finding.provenance)),
            "severity": max(
                (original.severity, ai_finding.severity),
                key=lambda severity: severity_rank[severity],
            ),
        })
    return merged


def build_summary(findings) -> ReviewSummary:
    counts = Counter(finding.severity for finding in findings)
    counts = {severity: counts.get(severity, 0) for severity in ("critical", "high", "medium", "low", "info")}
    if counts["critical"]:
        verdict = "block"
    elif counts["high"] or counts["medium"]:
        verdict = "request_changes"
    else:
        verdict = "approve"
    top_risks = [finding.title for finding in sorted(findings, key=lambda item: (item.severity, -item.confidence), reverse=True)[:3]]
    roadmap = (["Fix critical findings before merge"] if counts["critical"] else [])
    roadmap += (["Address high-severity security findings in this sprint"] if counts["high"] else [])
    roadmap += (["Clean up maintainability findings"] if counts["medium"] else [])
    roadmap = roadmap or ["No remediation work identified"]
    markdown = f"## Verdict: {verdict.replace('_', ' ').title()}\n\n" + \
        " | ".join(f"{key.title()}: {value}" for key, value in counts.items()) + "\n\n" + \
        "### Remediation roadmap\n" + "\n".join(f"- {item}" for item in roadmap)
    return ReviewSummary(verdict=verdict, counts=counts, top_risks=top_risks, roadmap=roadmap, markdown=markdown)


def merge_summary(findings, ai_summary: ReviewSummary | None) -> ReviewSummary:
    summary = build_summary(findings)
    if ai_summary is None:
        return summary
    return summary.model_copy(update={
        "score": ai_summary.score,
        "pr_summary": ai_summary.pr_summary,
        "major_issues": ai_summary.major_issues,
        "security_risk": ai_summary.security_risk,
        "recommended_actions": ai_summary.recommended_actions,
        "markdown": ai_summary.markdown or summary.markdown,
    })


def run_review(code: str, filename: str) -> Review:
    prepared = prepare_code(code, filename)
    findings = analyze(prepared.lines, prepared.language)
    scanner_run = scan_source(code, filename, prepared.language)
    findings.extend(_scanner_finding(item) for item in scanner_run.findings)
    ai_outcome = analyze_with_ai(code, filename, prepared.language, findings)
    findings = merge_ai_findings(findings, ai_outcome.findings)
    review_id = str(uuid4())
    findings = normalize_finding_ids(review_id, findings)
    warnings = scanner_run.warnings + ([ai_outcome.warning] if ai_outcome.warning else [])
    review = Review(
        id=review_id, filename=filename, language=prepared.language,
        lines=len(prepared.lines), findings=findings, summary=merge_summary(findings, ai_outcome.summary),
        tools=scanner_run.tools,
        coverage={
            "local_evidence_rules": "completed",
            "semgrep": "completed" if "semgrep" in scanner_run.tools else "skipped_or_failed",
            "bandit": "completed" if "bandit" in scanner_run.tools else ("not_applicable" if prepared.language != "python" else "skipped_or_failed"),
            "ruff": "completed" if "ruff" in scanner_run.tools else ("not_applicable" if prepared.language != "python" else "skipped_or_failed"),
            "ai": "completed" if ai_outcome.summary else "skipped_or_failed",
            "ai_provider": ai_outcome.provider or ai_outcome.status,
            "ai_model": ai_outcome.model or (
                "not_configured" if ai_outcome.status == "not_configured" else "unavailable"
            ),
            "knowledge_retrieval": ai_outcome.knowledge_status,
        },
        warnings=["Local evidence-backed rules are active."] + warnings,
    )
    REVIEWS[review.id] = review
    return review
