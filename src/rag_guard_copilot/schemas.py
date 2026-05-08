from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class User:
    user_id: str
    name: str
    department: str
    role: str
    allowed_groups: set[str]

    @property
    def handle(self) -> str:
        return f"{self.department}_{self.role}".strip().lower().replace(" ", "_")


@dataclass(frozen=True)
class Document:
    doc_id: str
    title: str
    group: str
    sensitivity: str
    content: str


@dataclass(frozen=True)
class RetrievalDecision:
    doc_id: str
    title: str
    group: str
    sensitivity: str
    score: float
    access_allowed: bool
    access_reason: str
    injection_flags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SecurityEvent:
    type: str
    doc_id: str
    title: str
    details: str


@dataclass(frozen=True)
class AuditEvent:
    user: User
    query: str
    allowed_docs: list[str]
    blocked_docs: list[str]
    blocked_reasons: dict[str, str]
    injection_doc_ids: list[str]
    masked_pii_count: int
    token_estimate: int
    latency_ms: float
    llm_enabled: bool


@dataclass(frozen=True)
class PipelineResult:
    user: User
    query: str
    answer: str
    allowed_docs: list[RetrievalDecision]
    blocked_docs: list[RetrievalDecision]
    retrieval_decisions: list[RetrievalDecision]
    security_events: list[SecurityEvent]
    masked_pii_count: int
    token_estimate: int
    latency_ms: float
    llm_enabled: bool
    audit_path: str
    injection_doc_ids: list[str]

    def to_legacy_dict(self) -> dict:
        return {
            "user": asdict(self.user),
            "answer": self.answer,
            "allowed_docs": [
                {
                    "doc_id": doc.doc_id,
                    "title": doc.title,
                    "group": doc.group,
                    "reason": doc.access_reason,
                    "score": round(doc.score, 3),
                }
                for doc in self.allowed_docs
            ],
            "blocked_docs": [
                {
                    "doc_id": doc.doc_id,
                    "title": doc.title,
                    "group": doc.group,
                    "reason": doc.access_reason,
                    "score": round(doc.score, 3),
                }
                for doc in self.blocked_docs
            ],
            "security_events": [asdict(event) for event in self.security_events],
            "retrieval_results": self.retrieval_decisions,
            "masked_pii_count": self.masked_pii_count,
            "token_estimate": self.token_estimate,
            "latency_ms": self.latency_ms,
            "llm_enabled": self.llm_enabled,
            "audit_path": self.audit_path,
        }
