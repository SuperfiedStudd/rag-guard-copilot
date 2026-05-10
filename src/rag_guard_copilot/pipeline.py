from __future__ import annotations

import time

from .audit import append_audit_event
from .config import DEFAULT_TOP_K, MAX_CONTEXT_CHUNKS, OPTIONAL_LLM_ENABLED
from .data_loader import get_document, load_document_objects, load_user_objects, resolve_user
from .policy_engine import evaluate_access
from .retrieval import search_documents
from .schemas import AuditEvent, PipelineResult, RetrievalDecision, SecurityEvent
from .security import detect_prompt_injection, mask_pii


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


REQUEST_INJECTION_BLOCK_REASON = "Prompt injection detected. Requested data exceeds role permissions."


def generate_demo_answer(query: str, safe_context: list[str], blocked_count: int) -> str:
    if not safe_context:
        return "No safe autonomous logistics documents were available for this query, so the copilot withheld an answer."
    snippets = "\n".join(f"- {item}" for item in safe_context[:MAX_CONTEXT_CHUNKS])
    blocked_notice = (
        f"\n\nAdditional retrieved candidates were withheld by policy or security controls: {blocked_count}."
        if blocked_count
        else ""
    )
    return (
        f"Secure autonomous logistics answer for: '{query}'\n\n"
        "Grounded context used after identity checks, prompt-injection filtering, and PII masking:\n"
        f"{snippets}{blocked_notice}"
    )


def run_secure_pipeline(query: str, user_ref: str, top_k: int | None = None) -> PipelineResult:
    start = time.perf_counter()
    user = resolve_user(user_ref, load_user_objects())
    documents = load_document_objects()
    ranked_results = search_documents(query, documents, top_k or DEFAULT_TOP_K)
    query_injection_flags = detect_prompt_injection(query)

    retrieval_decisions: list[RetrievalDecision] = []
    allowed_docs: list[RetrievalDecision] = []
    blocked_docs: list[RetrievalDecision] = []
    security_events: list[SecurityEvent] = []
    masked_context: list[str] = []
    blocked_reasons: dict[str, str] = {}
    injection_doc_ids: list[str] = []
    total_pii = 0

    if query_injection_flags:
        security_events.append(
            SecurityEvent(
                type="prompt_injection_flag",
                doc_id="query",
                title="User prompt",
                details=", ".join(query_injection_flags),
            )
        )

    for ranked_result in ranked_results:
        document = get_document(ranked_result.doc_id, documents)
        access_allowed, access_reason = evaluate_access(user, document)
        injection_flags = detect_prompt_injection(document.content)
        decision = RetrievalDecision(
            doc_id=document.doc_id,
            title=document.title,
            group=document.group,
            sensitivity=document.sensitivity,
            score=ranked_result.score,
            access_allowed=access_allowed,
            access_reason=access_reason,
            injection_flags=injection_flags,
        )
        retrieval_decisions.append(decision)

        if not decision.access_allowed:
            blocked_docs.append(decision)
            blocked_reasons[decision.doc_id] = decision.access_reason
            security_events.append(
                SecurityEvent(
                    type="access_block",
                    doc_id=decision.doc_id,
                    title=decision.title,
                    details=decision.access_reason,
                )
            )
            continue

        if query_injection_flags:
            blocked_docs.append(
                RetrievalDecision(
                    doc_id=decision.doc_id,
                    title=decision.title,
                    group=decision.group,
                    sensitivity=decision.sensitivity,
                    score=decision.score,
                    access_allowed=False,
                    access_reason=REQUEST_INJECTION_BLOCK_REASON,
                    injection_flags=decision.injection_flags,
                )
            )
            blocked_reasons[decision.doc_id] = REQUEST_INJECTION_BLOCK_REASON
            continue

        if decision.injection_flags:
            injection_doc_ids.append(decision.doc_id)
            blocked_docs.append(
                RetrievalDecision(
                    doc_id=decision.doc_id,
                    title=decision.title,
                    group=decision.group,
                    sensitivity=decision.sensitivity,
                    score=decision.score,
                    access_allowed=False,
                    access_reason="Prompt injection pattern detected in retrieved content.",
                    injection_flags=decision.injection_flags,
                )
            )
            blocked_reasons[decision.doc_id] = "Prompt injection pattern detected in retrieved content."
            security_events.append(
                SecurityEvent(
                    type="prompt_injection_flag",
                    doc_id=decision.doc_id,
                    title=decision.title,
                    details=", ".join(decision.injection_flags),
                )
            )
            continue

        masked_text, pii_counts = mask_pii(document.content)
        pii_total_for_doc = sum(pii_counts.values())
        total_pii += pii_total_for_doc
        if pii_total_for_doc:
            security_events.append(
                SecurityEvent(
                    type="pii_masked",
                    doc_id=decision.doc_id,
                    title=decision.title,
                    details=f"Masked {pii_total_for_doc} PII values: {pii_counts}",
                )
            )

        allowed_docs.append(decision)
        masked_context.append(masked_text)

    answer = (
        f"Request blocked. {REQUEST_INJECTION_BLOCK_REASON}"
        if query_injection_flags
        else generate_demo_answer(query, masked_context, blocked_count=len(blocked_docs))
    )
    token_estimate = estimate_tokens(query + "\n".join(masked_context))
    latency_ms = round((time.perf_counter() - start) * 1000, 1)
    audit_event = AuditEvent(
        user=user,
        query=query,
        allowed_docs=[doc.doc_id for doc in allowed_docs],
        blocked_docs=[doc.doc_id for doc in blocked_docs],
        blocked_reasons=blocked_reasons,
        injection_doc_ids=injection_doc_ids,
        masked_pii_count=total_pii,
        token_estimate=token_estimate,
        latency_ms=latency_ms,
        llm_enabled=OPTIONAL_LLM_ENABLED,
    )
    audit_path = append_audit_event(audit_event)

    return PipelineResult(
        user=user,
        query=query,
        answer=answer,
        allowed_docs=allowed_docs,
        blocked_docs=blocked_docs,
        retrieval_decisions=retrieval_decisions,
        security_events=security_events,
        masked_pii_count=total_pii,
        token_estimate=token_estimate,
        latency_ms=latency_ms,
        llm_enabled=OPTIONAL_LLM_ENABLED,
        audit_path=str(audit_path),
        injection_doc_ids=injection_doc_ids,
    )
