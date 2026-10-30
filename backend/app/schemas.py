from pathlib import PurePath
from hashlib import sha256
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


Severity = Literal["critical", "high", "medium", "low", "info"]
AgentName = Literal["code_analysis", "security", "remediation", "pr_summary"]
FindingType = Literal["security", "quality", "bug", "performance", "best_practice"]
FindingClassification = Literal["confirmed", "potential", "informational"]
FindingProvenance = Literal["local_rules", "semgrep", "bandit", "ruff", "ai"]
AIReviewVerdict = Literal["safe", "needs_changes", "high_risk"]


class Fix(BaseModel):
    explanation: str
    corrected_code: str
    references: list[str] = Field(default_factory=list)
    verified: bool = False


class Finding(BaseModel):
    id: str
    agent: AgentName
    classification: FindingClassification = "potential"
    provenance: list[FindingProvenance] = Field(default_factory=list)
    category: str
    cwe: str | None = None
    owasp_id: str | None = None
    severity: Severity
    line_start: int
    line_end: int
    title: str
    description: str
    evidence: str
    confidence: float = Field(ge=0, le=1)
    scanner: str = "local-evidence-rule"
    rule_id: str | None = None
    fix: Fix | None = None


class AIReviewFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(min_length=1, max_length=100)
    type: FindingType
    severity: Severity
    title: str = Field(min_length=1, max_length=300)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    confidence: float = Field(ge=0, le=1)
    description: str = Field(min_length=1, max_length=2_000)
    why_it_matters: str = Field(min_length=1, max_length=2_000)
    cwe: str | None = Field(default=None, pattern=r"^CWE-[0-9]{1,6}$")
    owasp: str | None = Field(default=None, pattern=r"^A[0-9]{2}:[0-9]{4}$")
    knowledge_references: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("knowledge_references")
    @classmethod
    def unique_knowledge_references(cls, references: list[str]) -> list[str]:
        if len(references) != len(set(references)):
            raise ValueError("Knowledge references must be unique")
        return references


class AIReviewRemediation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    finding_id: str = Field(min_length=1, max_length=100)
    recommendation: str = Field(min_length=1, max_length=2_000)
    fixed_code: str = Field(default="", max_length=20_000)


class AIReviewSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    verdict: AIReviewVerdict
    overall_score: int = Field(ge=0, le=100)
    pr_summary: str = Field(min_length=1, max_length=5_000)
    major_issues: list[str] = Field(default_factory=list, max_length=20)
    security_risk: str = Field(default="", max_length=500)
    recommended_actions: list[str] = Field(default_factory=list, max_length=20)


class AIReviewEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    code_analysis: list[AIReviewFinding] = Field(default_factory=list, max_length=100)
    security: list[AIReviewFinding] = Field(default_factory=list, max_length=100)
    remediation: list[AIReviewRemediation] = Field(default_factory=list, max_length=200)
    pr_summary: AIReviewSummary

    @model_validator(mode="after")
    def validate_role_sections(self) -> "AIReviewEnvelope":
        findings = self.code_analysis + self.security
        ids = [finding.id for finding in findings]
        if len(ids) != len(set(ids)):
            raise ValueError("AI finding IDs must be unique across role sections")
        if any(finding.type == "security" for finding in self.code_analysis):
            raise ValueError("Code analysis findings cannot use the security category")
        if any(finding.type != "security" for finding in self.security):
            raise ValueError("Security findings must use the security category")
        remediation_ids = [item.finding_id for item in self.remediation]
        if len(remediation_ids) != len(set(remediation_ids)):
            raise ValueError("Remediation finding IDs must be unique")
        if set(ids) != set(remediation_ids):
            raise ValueError("Every finding must have exactly one remediation")
        return self

    @property
    def findings(self) -> list[AIReviewFinding]:
        return self.code_analysis + self.security

    @property
    def remediations(self) -> dict[str, AIReviewRemediation]:
        return {item.finding_id: item for item in self.remediation}

    @property
    def summary(self) -> AIReviewSummary:
        return self.pr_summary

    @field_validator("code_analysis", "security")
    @classmethod
    def unique_findings_per_role(cls, findings: list[AIReviewFinding]) -> list[AIReviewFinding]:
        ids = [finding.id for finding in findings]
        if len(ids) != len(set(ids)):
            raise ValueError("AI finding IDs must be unique")
        return findings


def review_scoped_finding_id(review_id: str, finding: Finding) -> str:
    identity = ":".join(str(value) for value in (
        review_id, finding.id, finding.agent, finding.scanner, finding.rule_id,
        finding.line_start, finding.line_end, finding.title,
    ))
    return sha256(identity.encode("utf-8")).hexdigest()[:32]


def normalize_finding_ids(review_id: str, findings: list[Finding]) -> list[Finding]:
    normalized: list[Finding] = []
    seen: set[str] = set()
    for finding in findings:
        candidate = review_scoped_finding_id(review_id, finding)
        suffix = 1
        unique_id = candidate
        while unique_id in seen:
            suffix += 1
            unique_id = f"{candidate}-{suffix}"
        seen.add(unique_id)
        normalized.append(finding.model_copy(update={"id": unique_id}))
    return normalized


class ReviewRequest(BaseModel):
    code: str = Field(min_length=1, max_length=100_000)
    filename: str = Field(default="snippet.py", min_length=1, max_length=255)

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        if any(ord(character) < 32 for character in value):
            raise ValueError("filename contains control characters")
        if PurePath(value).name != value or value in {".", ".."}:
            raise ValueError("filename must be a single file name")
        if PurePath(value).suffix.lower() not in {".py", ".java"}:
            raise ValueError("only .py and .java files are supported")
        return value

    @field_validator("code")
    @classmethod
    def validate_source_encoding_and_size(cls, value: str) -> str:
        import os

        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise ValueError("source must be valid UTF-8") from error
        if len(encoded) > int(os.getenv("MAX_SOURCE_BYTES", "100000")):
            raise ValueError("source exceeds the configured byte limit")
        return value

    model_config = {"str_strip_whitespace": True}

class ReviewSummary(BaseModel):
    verdict: Literal["approve", "request_changes", "block"]
    counts: dict[str, int]
    top_risks: list[str]
    roadmap: list[str]
    markdown: str
    score: int | None = Field(default=None, ge=0, le=100)
    pr_summary: str = ""
    major_issues: list[str] = Field(default_factory=list)
    security_risk: str = ""
    recommended_actions: list[str] = Field(default_factory=list)


class Review(BaseModel):
    id: str
    filename: str
    language: Literal["python", "java", "unknown"]
    lines: int
    findings: list[Finding]
    summary: ReviewSummary
    status: Literal["queued", "running", "completed", "completed-with-warnings", "failed"] = "completed"
    job_id: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    tools: list[str] = Field(default_factory=list)
    coverage: dict[str, str] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class ChatRequest(BaseModel):
    review_id: str
    message: str = Field(min_length=1, max_length=4_000)


class ChatResponse(BaseModel):
    answer: str
    sources: list[str] = Field(default_factory=list)
