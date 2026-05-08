from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from rag_guard_copilot.audit import load_audit_log
from rag_guard_copilot.data_loader import load_documents, load_users
from rag_guard_copilot.pipeline import run_secure_pipeline


st.set_page_config(page_title="RAG Guard Copilot", page_icon="🛡️", layout="wide")


@st.cache_data
def get_users() -> pd.DataFrame:
    return load_users()


@st.cache_data
def get_documents() -> pd.DataFrame:
    return load_documents()


def render_query_tab(users_df: pd.DataFrame, documents_df: pd.DataFrame) -> None:
    del documents_df
    st.subheader("Identity-aware assistant")
    user_options = users_df.apply(
        lambda row: f"{row['user_id']} | {row['name']} | {row['department']} | {row['role']}",
        axis=1,
    ).tolist()
    selected_label = st.selectbox("Simulated user", user_options, index=0)
    selected_user_id = selected_label.split(" | ")[0]
    query = st.text_area(
        "Ask a question",
        value="Summarize finance and HR updates relevant to me.",
        height=110,
    )

    if st.button("Run secure retrieval", type="primary", use_container_width=True):
        with st.spinner("Checking access, screening prompt injection, and masking PII..."):
            result = run_secure_pipeline(query, selected_user_id)
        st.session_state["last_result"] = result

    result = st.session_state.get("last_result")
    if not result:
        st.info("Run a query to see secure retrieval, blocked documents, and audit details.")
        return

    left, right = st.columns([1.5, 1])
    with left:
        st.markdown("### Assistant output")
        st.code(result.answer, language="markdown")

        st.markdown("### Allowed context")
        if result.allowed_docs:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "doc_id": doc.doc_id,
                            "title": doc.title,
                            "group": doc.group,
                            "reason": doc.access_reason,
                            "score": round(doc.score, 3),
                        }
                        for doc in result.allowed_docs
                    ]
                ),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.warning("No documents cleared policy checks for this query.")

    with right:
        st.markdown("### Run summary")
        st.metric("Masked PII", result.masked_pii_count)
        st.metric("Token estimate", result.token_estimate)
        st.metric("Latency (ms)", result.latency_ms)
        st.metric("Optional LLM enabled", "No" if not result.llm_enabled else "Yes")
        st.caption(f"Audit event: {result.audit_path}")

        st.markdown("### Blocked context")
        if result.blocked_docs:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "doc_id": doc.doc_id,
                            "title": doc.title,
                            "group": doc.group,
                            "reason": doc.access_reason,
                            "score": round(doc.score, 3),
                        }
                        for doc in result.blocked_docs
                    ]
                ),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.success("No documents were blocked in this retrieval set.")

    st.markdown("### All retrieved candidates")
    table = pd.DataFrame(
        [
            {
                "doc_id": item.doc_id,
                "title": item.title,
                "group": item.group,
                "sensitivity": item.sensitivity,
                "score": round(item.score, 3),
                "access_allowed": item.access_allowed,
                "access_reason": item.access_reason,
                "injection_flags": ", ".join(item.injection_flags) if item.injection_flags else "",
            }
            for item in result.retrieval_decisions
        ]
    )
    st.dataframe(table, use_container_width=True, hide_index=True)


def render_audit_tab() -> None:
    st.subheader("Audit log")
    audit_df = load_audit_log()
    if audit_df.empty:
        st.info("No audit events yet. Run a query in the assistant tab first.")
        return
    st.dataframe(audit_df.sort_values("timestamp", ascending=False), use_container_width=True, hide_index=True)


def render_events_tab() -> None:
    st.subheader("Security events")
    result = st.session_state.get("last_result")
    if not result:
        st.info("Run a query to populate access blocks, injection flags, and PII masking events.")
        return
    events = result.security_events
    if not events:
        st.success("No security events were raised for the most recent query.")
        return
    st.dataframe(pd.DataFrame([event.__dict__ for event in events]), use_container_width=True, hide_index=True)


def render_eval_tab(users_df: pd.DataFrame, documents_df: pd.DataFrame) -> None:
    del users_df, documents_df
    st.subheader("Evaluation scenarios")
    scenarios = [
        {
            "scenario": "Finance analyst can retrieve finance content",
            "user_id": "finance_analyst",
            "query": "What happened in the Q3 finance plan?",
            "expected": "finance_allowed",
        },
        {
            "scenario": "HR specialist is blocked from legal memo",
            "user_id": "u_hr_01",
            "query": "Show the merger risk memo.",
            "expected": "legal_blocked",
        },
        {
            "scenario": "Prompt injection doc is flagged",
            "user_id": "u_it_01",
            "query": "Any security runbook updates?",
            "expected": "injection_flagged",
        },
    ]

    rows = []
    for scenario in scenarios:
        result = run_secure_pipeline(scenario["query"], scenario["user_id"])
        finance_allowed = any(doc.group == "finance" for doc in result.allowed_docs)
        legal_blocked = any(doc.group == "legal" for doc in result.blocked_docs)
        injection_flagged = any(event.type == "prompt_injection_flag" for event in result.security_events)

        passed = {
            "finance_allowed": finance_allowed,
            "legal_blocked": legal_blocked,
            "injection_flagged": injection_flagged,
        }[scenario["expected"]]

        rows.append(
            {
                "scenario": scenario["scenario"],
                "user_id": scenario["user_id"],
                "query": scenario["query"],
                "passed": passed,
                "allowed_docs": len(result.allowed_docs),
                "blocked_docs": len(result.blocked_docs),
                "security_events": len(result.security_events),
            }
        )

    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    pass_rate = sum(1 for row in rows if row["passed"]) / len(rows)
    st.metric("Pass rate", f"{pass_rate:.0%}")


def main() -> None:
    users_df = get_users()
    documents_df = get_documents()

    st.title("RAG Guard Copilot")
    st.caption("Demo-ready identity-aware RAG security for enterprise AI assistants.")

    with st.sidebar:
        st.markdown("### Demo scope")
        st.write("Streamlit is a thin demo surface over the backend policy-aware RAG security pipeline.")
        st.write("Access control is mocked with local sample users and document groups.")
        st.write("Retrieval uses local TF-IDF search with no paid API dependency.")
        st.write("Optional model calls are disabled by default.")

        st.markdown("### Sample users")
        st.dataframe(
            users_df[["user_id", "name", "department", "role", "allowed_groups"]],
            use_container_width=True,
            hide_index=True,
        )

    query_tab, audit_tab, events_tab, eval_tab = st.tabs(
        ["Query Assistant", "Access Audit", "Security Events", "Evaluation"]
    )

    with query_tab:
        render_query_tab(users_df, documents_df)
    with audit_tab:
        render_audit_tab()
    with events_tab:
        render_events_tab()
    with eval_tab:
        render_eval_tab(users_df, documents_df)


if __name__ == "__main__":
    main()
