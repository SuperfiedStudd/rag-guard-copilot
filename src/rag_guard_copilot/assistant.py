from __future__ import annotations

import time

import pandas as pd

from .audit import append_audit_event
from .config import DEFAULT_TOP_K, MAX_CONTEXT_CHUNKS, OPTIONAL_LLM_ENABLED
from .retrieval import RetrievalResult, build_index, search_documents
from .security import check_document_access, detect_prompt_injection, get_user_record, mask_pii


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def generate_demo_answer(query: str, safe_context: list[str]) -> str:
    if not safe_context:
        return "No safe documents were available for this query, so the assistant withheld an answer."
    snippets = "\n".join(f"- {item}" for item in safe_context[:MAX_CONTEXT_CHUNKS])
    return (
        f"Demo answer for: '{query}'\n\n"
        "Grounded context used after access checks, injection filtering, and PII masking:\n"
        f"{snippets}"
    )


def run_secure_query(query: str, user_id: str, users_df: pd.DataFrame, documents_df: pd.DataFrame) -> dict:
    start = time.perf_counter()
    user = get_user_record(users_df, user_id)
    vectorizer, matrix = build_index(documents_df)
    raw_results = search_documents(query, documents_df, vectorizer, matrix, DEFAULT_TOP_K)

    retrieval_results: list[RetrievalResult] = []
    allowed_docs: list[dict] = []
    blocked_docs: list[dict] = []
    security_events: list[dict] = []
    masked_context: list[str] = []
    blocked_reasons: dict[str, str] = {}
    injection_doc_ids: list[str] = []
    total_pii = 0

    for row in raw_results.to_dict(orient="records"):
        access = check_document_access(user, row["group"])
        injection_flags = detect_prompt_injection(row["content"])
        result = RetrievalResult(
            doc_id=row["doc_id"],
            title=row["title"],
            group=row["group"],
            sensitivity=row["sensitivity"],
            content=row["content"],
            score=float(row["score"]),
            access_allowed=access.allowed,
            access_reason=access.reason,
            injection_flags=injection_flags,
        )
        retrieval_results.append(result)

        if not access.allowed:
            blocked_docs.append(
                {
                    "doc_id": result.doc_id,
                    "title": result.title,
                    "group": result.group,
                    "reason": result.access_reason,
                    "score": round(result.score, 3),
                }
            )
            blocked_reasons[result.doc_id] = result.access_reason
            security_events.append(
                {
                    "type": "access_block",
                    "doc_id": result.doc_id,
                    "title": result.title,
                    "details": result.access_reason,
                }
            )
            continue

        if result.injection_flags:
            injection_doc_ids.append(result.doc_id)
            security_events.append(
                {
                    "type": "prompt_injection_flag",
                    "doc_id": result.doc_id,
                    "title": result.title,
                    "details": ", ".join(result.injection_flags),
                }
            )
            blocked_docs.append(
                {
                    "doc_id": result.doc_id,
                    "title": result.title,
                    "group": result.group,
                    "reason": "Prompt injection pattern detected in retrieved content.",
                    "score": round(result.score, 3),
                }
            )
            blocked_reasons[result.doc_id] = "Prompt injection pattern detected in retrieved content."
            continue

        masked_text, pii_counts = mask_pii(result.content)
        pii_total_for_doc = sum(pii_counts.values())
        total_pii += pii_total_for_doc
        if pii_total_for_doc:
            security_events.append(
                {
                    "type": "pii_masked",
                    "doc_id": result.doc_id,
                    "title": result.title,
                    "details": f"Masked {pii_total_for_doc} PII values: {pii_counts}",
                }
            )

        allowed_docs.append(
            {
                "doc_id": result.doc_id,
                "title": result.title,
                "group": result.group,
                "reason": result.access_reason,
                "score": round(result.score, 3),
            }
        )
        masked_context.append(masked_text)

    answer = generate_demo_answer(query, masked_context)
    token_estimate = estimate_tokens(query + "\n".join(masked_context))
    latency_ms = round((time.perf_counter() - start) * 1000, 1)

    audit_event = {
        "user": user,
        "query": query,
        "allowed_docs": [doc["doc_id"] for doc in allowed_docs],
        "blocked_docs": [doc["doc_id"] for doc in blocked_docs],
        "blocked_reasons": blocked_reasons,
        "injection_doc_ids": injection_doc_ids,
        "masked_pii_count": total_pii,
        "token_estimate": token_estimate,
        "latency_ms": latency_ms,
        "llm_enabled": OPTIONAL_LLM_ENABLED,
    }
    append_audit_event(audit_event)

    return {
        "user": user,
        "answer": answer,
        "allowed_docs": allowed_docs,
        "blocked_docs": blocked_docs,
        "security_events": security_events,
        "retrieval_results": retrieval_results,
        "masked_pii_count": total_pii,
        "token_estimate": token_estimate,
        "latency_ms": latency_ms,
        "llm_enabled": OPTIONAL_LLM_ENABLED,
    }
