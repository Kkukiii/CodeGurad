import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..schemas import Finding


_TOKEN = re.compile(r"[A-Z]{2,}(?=[A-Z][a-z]|\b)|[A-Z]?[a-z]+|\d+")
_STOP_WORDS = {
    "and", "are", "as", "at", "be", "by", "code", "for", "from",
    "in", "is", "it", "of", "on", "or", "that", "the", "this",
    "to", "use", "with", "class", "def", "false", "none", "null",
    "pass", "return", "self", "true", "value",
}


class KnowledgeRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=1)
    language: Literal["python", "java"]
    type: str
    category: str
    severity: str
    cwe: str | None = None
    owasp: str | None = None
    title: str
    description: str
    vulnerable_code: str = ""
    fixed_code: str = ""
    why_it_matters: str = ""
    remediation: str = ""
    detection_signals: list[str] = Field(default_factory=list)
    rag_keywords: list[str] = Field(default_factory=list)


def load_knowledge(path: Path | None = None) -> list[KnowledgeRecord]:
    source = path or Path(__file__).parents[2] / "knowledge base" / "ai_modules.json"
    payload = json.loads(source.read_text(encoding="utf-8"))
    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        raise ValueError("Knowledge base must contain a records array")
    return [KnowledgeRecord.model_validate(record) for record in records]


def _tokens(value: str) -> set[str]:
    return {
        token.lower()
        for token in _TOKEN.findall(value)
        if token.lower() not in _STOP_WORDS and len(token) > 1
    }


def _token_counts(value: str) -> Counter[str]:
    return Counter(
        token.lower()
        for token in _TOKEN.findall(value)
        if token.lower() not in _STOP_WORDS and len(token) > 1
    )


def retrieve_knowledge(
    code: str,
    language: str,
    findings: list[Finding] | None = None,
    *,
    limit: int = 3,
    path: Path | None = None,
) -> list[KnowledgeRecord]:
    if limit < 1:
        raise ValueError("Knowledge retrieval limit must be positive")

    evidence_terms = " ".join(
        " ".join((
            finding.title,
            finding.category,
            finding.rule_id or "",
            finding.cwe or "",
            finding.evidence,
        ))
        for finding in findings or []
    )
    query = _token_counts(f"{code}\n{evidence_terms}")
    candidates = [record for record in load_knowledge(path) if record.language == language]
    if not query or not candidates:
        return []

    fields: dict[str, tuple[set[str], set[str], set[str]]] = {}
    document_frequency: Counter[str] = Counter()
    for record in candidates:
        strong_terms = _tokens(f"{record.title} {record.category} {record.cwe or ''} {record.owasp or ''}")
        signal_terms = _tokens(" ".join(record.detection_signals + record.rag_keywords))
        context_terms = _tokens(
            f"{record.description} {record.vulnerable_code} {record.fixed_code} "
            f"{record.why_it_matters} {record.remediation}"
        )
        fields[record.id] = (strong_terms, signal_terms, context_terms)
        document_frequency.update(strong_terms | signal_terms | context_terms)

    record_count = len(candidates)
    ranked: list[tuple[float, str, KnowledgeRecord]] = []
    for record in candidates:
        strong_terms, signal_terms, context_terms = fields[record.id]
        score = 0.0
        for term, frequency in query.items():
            document_frequency_count = document_frequency[term]
            if not document_frequency_count:
                continue
            inverse_document_frequency = math.log1p(
                (record_count - document_frequency_count + 0.5)
                / (document_frequency_count + 0.5)
            )
            query_weight = min(frequency, 3)
            score += query_weight * inverse_document_frequency * (
                4 * (term in strong_terms)
                + 2 * (term in signal_terms)
                + (term in context_terms)
            )
        if score > 0:
            ranked.append((score, record.id, record))

    ranked.sort(key=lambda result: (-result[0], result[1]))
    return [record for _, _, record in ranked[:limit]]
