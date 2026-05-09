from __future__ import annotations

import html
import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
STYLES_PATH = ROOT / "styles" / "sandstone_light.css"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from rag_guard_copilot.audit import load_audit_log
from rag_guard_copilot.data_loader import load_documents, load_users
from rag_guard_copilot.pipeline import run_secure_pipeline
from rag_guard_copilot.security import mask_pii


st.set_page_config(
    page_title="RAG Guard Copilot",
    page_icon="RG",
    layout="wide",
    initial_sidebar_state="expanded",
)
st.set_option("client.toolbarMode", "minimal")


PAGE_OPTIONS = [
    "Secure Workspace",
    "Decision Explorer",
    "Audit Trail",
    "Scenario Lab",
]

DEFAULT_QUERY = "Summarize finance and HR updates relevant to me."
SCENARIOS = [
    {
        "id": "finance_happy_path",
        "title": "Finance access with PII masking",
        "description": "Shows allowed finance retrieval, redacted contact details, and retained audit evidence.",
        "user_id": "u_fin_01",
        "query": "What happened in the Q3 finance plan?",
        "expected": "finance_allowed",
        "cta": "Finance happy path",
    },
    {
        "id": "legal_access_denial",
        "title": "Legal access denial",
        "description": "Shows identity-aware access control denying a legal memo to a non-legal user.",
        "user_id": "u_hr_01",
        "query": "Show the merger risk memo.",
        "expected": "legal_blocked",
        "cta": "Access denial",
    },
    {
        "id": "prompt_injection_trap",
        "title": "Prompt injection trap",
        "description": "Shows malicious retrieved content being quarantined before the answer path.",
        "user_id": "u_it_01",
        "query": "Any security runbook updates?",
        "expected": "injection_flagged",
        "cta": "Injection trap",
    },
]


@st.cache_data(show_spinner=False)
def get_users() -> pd.DataFrame:
    return load_users()


@st.cache_data(show_spinner=False)
def get_documents() -> pd.DataFrame:
    return load_documents()


def get_styles() -> str:
    return STYLES_PATH.read_text(encoding="utf-8")


def inject_styles() -> None:
    st.markdown(f"<style>{get_styles()}</style>", unsafe_allow_html=True)


def init_session_state(users_df: pd.DataFrame) -> None:
    first_user_id = users_df.iloc[0]["user_id"]
    defaults = {
        "page_name": PAGE_OPTIONS[0],
        "selected_user_id": first_user_id,
        "query_text": DEFAULT_QUERY,
        "retrieval_depth": 5,
        "lab_scenario_id": SCENARIOS[0]["id"],
        "last_scenario_id": SCENARIOS[0]["id"],
        "last_result": None,
        "lab_result": None,
        "regression_rows": [],
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def parse_allowed_groups(raw_value: str) -> list[str]:
    return [item.strip() for item in str(raw_value).split("|") if item.strip()]


def initials_for_name(name: str) -> str:
    parts = [part[:1].upper() for part in str(name).split() if part]
    return "".join(parts[:2]) or "RG"


def escape_markup(value: object) -> str:
    return html.escape(str(value)).replace("\n", "<br>")


def parse_json_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return []
    try:
        loaded = json.loads(str(value))
    except json.JSONDecodeError:
        return []
    if isinstance(loaded, list):
        return [str(item) for item in loaded]
    return []


def parse_json_dict(value: object) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items()}
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return {}
    try:
        loaded = json.loads(str(value))
    except json.JSONDecodeError:
        return {}
    if isinstance(loaded, dict):
        return {str(key): str(item) for key, item in loaded.items()}
    return {}


def pill_html(values: list[str], tone: str = "neutral") -> str:
    if not values:
        return "<span class='sand-pill sand-pill-neutral'>None</span>"
    return "".join(
        f"<span class='sand-pill sand-pill-{tone}'>{escape_markup(value)}</span>" for value in values
    )


def format_user_label(user_id: str, users_df: pd.DataFrame) -> str:
    user_row = users_df.set_index("user_id").loc[user_id]
    return f"{user_row['name']} | {user_row['department']} | {user_row['role']}"


def result_to_rows(result) -> pd.DataFrame:
    blocked_lookup = {doc.doc_id: doc for doc in result.blocked_docs}
    rows = []
    for decision in result.retrieval_decisions:
        blocked_version = blocked_lookup.get(decision.doc_id)
        final_status = "Blocked" if blocked_version else "Allowed"
        final_reason = blocked_version.access_reason if blocked_version else decision.access_reason
        rows.append(
            {
                "status": final_status,
                "doc_id": decision.doc_id,
                "title": decision.title,
                "group": decision.group,
                "sensitivity": decision.sensitivity,
                "score": round(decision.score, 3),
                "reason": final_reason,
                "injection_flags": ", ".join(decision.injection_flags) if decision.injection_flags else "",
            }
        )
    return pd.DataFrame(rows)


def result_doc_table(docs: list) -> pd.DataFrame:
    if not docs:
        return pd.DataFrame(columns=["doc_id", "title", "group", "reason", "score"])
    return pd.DataFrame(
        [
            {
                "doc_id": doc.doc_id,
                "title": doc.title,
                "group": doc.group,
                "reason": doc.access_reason,
                "score": round(doc.score, 3),
            }
            for doc in docs
        ]
    )


def build_audit_view(audit_df: pd.DataFrame) -> pd.DataFrame:
    if audit_df.empty:
        return audit_df

    view = audit_df.copy()
    view["timestamp"] = pd.to_datetime(view["timestamp"], errors="coerce")
    view["allowed_doc_ids"] = view["allowed_docs"].apply(parse_json_list)
    view["blocked_doc_ids"] = view["blocked_docs"].apply(parse_json_list)
    view["blocked_reason_map"] = view["blocked_reasons"].apply(parse_json_dict)
    view["injection_doc_ids_list"] = view["injection_doc_ids"].apply(parse_json_list)
    view["allowed_count"] = view["allowed_doc_ids"].apply(len)
    view["blocked_count"] = view["blocked_doc_ids"].apply(len)
    view["injection_count"] = view["injection_doc_ids_list"].apply(len)
    view["safe_retrieval"] = view["allowed_count"] > 0
    view["had_intervention"] = (view["blocked_count"] > 0) | (view["injection_count"] > 0)
    view["timestamp_label"] = view["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    return view.sort_values("timestamp", ascending=False)


def render_page_header(kicker: str, title: str, description: str, badges: list[str]) -> None:
    badge_markup = "".join(f"<span class='page-badge'>{escape_markup(badge)}</span>" for badge in badges)
    badges_block = f"<div class='page-badges'>{badge_markup}</div>" if badge_markup else ""
    markup = (
        "<div class='page-shell'>"
        f"<div class='page-kicker'>{escape_markup(kicker)}</div>"
        "<div class='page-header-row'>"
        "<div class='page-copy'>"
        f"<div class='page-title'>{escape_markup(title)}</div>"
        f"<div class='page-description'>{escape_markup(description)}</div>"
        "</div>"
        f"{badges_block}"
        "</div>"
        "</div>"
    )
    st.markdown(markup, unsafe_allow_html=True)


def render_stat_cards(metrics: list[tuple[str, str, str]]) -> None:
    columns = st.columns(len(metrics))
    for column, metric in zip(columns, metrics, strict=True):
        label, value, meta = metric
        with column:
            st.markdown(
                f"""
                <div class="stat-card">
                    <div class="stat-label">{escape_markup(label)}</div>
                    <div class="stat-value">{escape_markup(value)}</div>
                    <div class="stat-meta">{escape_markup(meta)}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_identity_panel(user_row: pd.Series) -> None:
    allowed_groups = parse_allowed_groups(user_row["allowed_groups"])
    role_access_note = "Role-based internal access enabled." if user_row["role"].lower() in {
        "manager",
        "director",
        "counsel",
    } else "Role-based internal access not expanded beyond explicit groups."
    st.markdown(
        f"""
        <div class="panel-copy">
            <div class="panel-eyebrow">Resolved identity</div>
            <div class="identity-name">{escape_markup(user_row['name'])}</div>
            <div class="panel-description">
                {escape_markup(user_row['department'])} / {escape_markup(user_row['role'])}
            </div>
            <div class="pill-row">{pill_html(allowed_groups, tone="neutral")}</div>
            <div class="support-copy">{escape_markup(role_access_note)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_decision_summary(result) -> None:
    access_blocks = sum(1 for event in result.security_events if event.type == "access_block")
    injection_flags = sum(1 for event in result.security_events if event.type == "prompt_injection_flag")
    pii_events = sum(1 for event in result.security_events if event.type == "pii_masked")
    explanation_points = [
        f"Identity resolved to {result.user.name} in {result.user.department} as {result.user.role}.",
        f"{len(result.allowed_docs)} documents cleared access policy, injection screening, and masking requirements.",
        f"{access_blocks} access blocks were raised by group policy." if access_blocks else "No access policy blocks were raised in this run.",
        f"{injection_flags} retrieved documents were quarantined for prompt injection patterns."
        if injection_flags
        else "No prompt injection phrases were detected in the retrieved context.",
        f"{result.masked_pii_count} PII values were redacted across {pii_events} documents."
        if result.masked_pii_count
        else "No PII values required masking in the allowed context.",
        f"Audit evidence appended to {result.audit_path}.",
    ]
    bullet_markup = "".join(f"<li>{escape_markup(point)}</li>" for point in explanation_points)
    st.markdown(
        f"""
        <div class="rich-card">
            <div class="panel-eyebrow">Why this decision happened</div>
            <ul class="decision-list">{bullet_markup}</ul>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_answer_panel(result) -> None:
    st.markdown(
        f"""
        <div class="answer-card">
            <div class="panel-eyebrow">Assistant output</div>
            <div class="answer-text">{escape_markup(result.answer)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_security_event_cards(result) -> None:
    if not result.security_events:
        st.success("No security events were raised for the current run.")
        return

    for event in result.security_events:
        tone = {
            "access_block": "warning",
            "prompt_injection_flag": "danger",
            "pii_masked": "success",
        }.get(event.type, "neutral")
        st.markdown(
            f"""
            <div class="event-card event-card-{tone}">
                <div class="event-title">{escape_markup(event.type.replace('_', ' ').title())}</div>
                <div class="event-doc">{escape_markup(event.title)} ({escape_markup(event.doc_id)})</div>
                <div class="event-details">{escape_markup(event.details)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_trace_steps(result) -> None:
    access_blocks = sum(1 for event in result.security_events if event.type == "access_block")
    injection_flags = sum(1 for event in result.security_events if event.type == "prompt_injection_flag")
    trace_steps = [
        (
            "1. Identity resolution",
            f"Mapped request to {result.user.user_id} with role {result.user.role} and policy-scoped groups.",
        ),
        (
            "2. Candidate retrieval",
            f"Ranked {len(result.retrieval_decisions)} documents with local TF-IDF retrieval.",
        ),
        (
            "3. Access policy",
            f"Allowed {len(result.allowed_docs)} documents and blocked {access_blocks} by document-group policy.",
        ),
        (
            "4. Prompt defense",
            f"Flagged {injection_flags} malicious retrieval candidates before answer construction.",
        ),
        (
            "5. PII masking",
            f"Redacted {result.masked_pii_count} sensitive values from allowed context.",
        ),
        (
            "6. Audit logging",
            f"Wrote structured trace evidence to {result.audit_path}.",
        ),
    ]
    for title, description in trace_steps:
        st.markdown(
            f"""
            <div class="trace-step">
                <div class="trace-title">{escape_markup(title)}</div>
                <div class="trace-description">{escape_markup(description)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_masking_demo(result, documents_df: pd.DataFrame) -> None:
    if not result.allowed_docs:
        st.info("No allowed documents are available to demonstrate masking for this run.")
        return

    documents_lookup = documents_df.set_index("doc_id")
    st.caption("Demo/sample data. Raw snippets are shown only to illustrate masking behavior in the local review app.")
    for doc in result.allowed_docs:
        raw_content = documents_lookup.loc[doc.doc_id]["content"]
        masked_text, pii_counts = mask_pii(str(raw_content))
        pii_total = sum(pii_counts.values())
        summary = f"{doc.title} | {doc.group} | {pii_total} values masked"
        with st.expander(summary, expanded=False):
            if pii_counts:
                st.markdown(
                    f"<div class='pill-row'>{pill_html([f'{label}: {count}' for label, count in pii_counts.items()], tone='success')}</div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    "<div class='support-copy'>No PII values were detected in this document.</div>",
                    unsafe_allow_html=True,
                )
            left, right = st.columns(2)
            with left:
                st.markdown("##### Raw snippet")
                st.code(str(raw_content), language="text")
            with right:
                st.markdown("##### Masked snippet")
                st.code(masked_text, language="text")


def render_candidate_explainers(result, documents_df: pd.DataFrame, interventions_only: bool = False) -> None:
    candidate_rows = result_to_rows(result)
    documents_lookup = documents_df.set_index("doc_id")
    if interventions_only:
        candidate_rows = candidate_rows[candidate_rows["status"] == "Blocked"]

    if candidate_rows.empty:
        st.info("No candidates match the current filters.")
        return

    for row in candidate_rows.to_dict(orient="records"):
        doc_content = documents_lookup.loc[row["doc_id"]]["content"]
        title = f"{row['status']} | {row['title']} | {row['group']}"
        with st.expander(title, expanded=False):
            st.markdown(
                f"""
                <div class="support-grid">
                    <div><span class="field-label">Document</span><span class="field-value">{escape_markup(row['doc_id'])}</span></div>
                    <div><span class="field-label">Sensitivity</span><span class="field-value">{escape_markup(row['sensitivity'])}</span></div>
                    <div><span class="field-label">Retrieval score</span><span class="field-value">{escape_markup(row['score'])}</span></div>
                    <div><span class="field-label">Decision</span><span class="field-value">{escape_markup(row['reason'])}</span></div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if row["injection_flags"]:
                st.markdown(
                    f"<div class='pill-row'>{pill_html([flag.strip() for flag in row['injection_flags'].split(',')], tone='danger')}</div>",
                    unsafe_allow_html=True,
                )
            st.caption("Demo/sample content preview")
            st.code(str(doc_content), language="text")


def compute_observability_metrics(audit_view: pd.DataFrame) -> list[tuple[str, str, str]]:
    if audit_view.empty:
        return [
            ("Audited runs", "0", "No audit rows recorded yet"),
            ("Safe retrieval rate", "0%", "Grounded runs with safe context"),
            ("Blocked requests", "0", "Runs with policy intervention"),
            ("Median latency", "0 ms", "Local end-to-end runtime"),
        ]

    total_runs = len(audit_view)
    safe_rate = audit_view["safe_retrieval"].mean()
    blocked_runs = int((audit_view["blocked_count"] > 0).sum())
    median_latency = float(audit_view["latency_ms"].median())
    return [
        ("Audited runs", str(total_runs), "Structured evidence in the audit ledger"),
        ("Safe retrieval rate", f"{safe_rate:.0%}", "Runs with at least one allowed document"),
        ("Blocked requests", str(blocked_runs), "Requests with access or guardrail interventions"),
        ("Median latency", f"{median_latency:.1f} ms", "Observed local workflow latency"),
    ]


def set_result_state(
    result,
    user_id: str,
    query: str,
    top_k: int,
    *,
    scenario_id: str | None = None,
    sync_inputs: bool = False,
) -> None:
    if sync_inputs:
        st.session_state["selected_user_id"] = user_id
        st.session_state["query_text"] = query
        st.session_state["retrieval_depth"] = top_k
    st.session_state["last_result"] = result
    if scenario_id:
        st.session_state["lab_result"] = result
        st.session_state["last_scenario_id"] = scenario_id


def run_query_and_refresh(
    user_id: str,
    query: str,
    top_k: int,
    *,
    scenario_id: str | None = None,
    sync_inputs: bool = False,
) -> None:
    with st.spinner("Evaluating access policy, prompt injection defense, masking, and audit logging..."):
        result = run_secure_pipeline(query.strip(), user_id, top_k=top_k)
    set_result_state(
        result,
        user_id,
        query.strip(),
        top_k,
        scenario_id=scenario_id,
        sync_inputs=sync_inputs,
    )
    st.rerun()


def run_regression_suite() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for scenario in SCENARIOS:
        result = run_secure_pipeline(scenario["query"], scenario["user_id"])
        actual_checks = {
            "finance_allowed": any(doc.group == "finance" for doc in result.allowed_docs),
            "legal_blocked": any(doc.group == "legal" for doc in result.blocked_docs),
            "injection_flagged": any(event.type == "prompt_injection_flag" for event in result.security_events),
        }
        passed = actual_checks[scenario["expected"]]
        rows.append(
            {
                "scenario": scenario["title"],
                "user_id": scenario["user_id"],
                "query": scenario["query"],
                "expected_signal": scenario["expected"],
                "passed": passed,
                "allowed_docs": len(result.allowed_docs),
                "blocked_docs": len(result.blocked_docs),
                "security_events": len(result.security_events),
            }
        )
    return rows


def render_sidebar(users_df: pd.DataFrame, documents_df: pd.DataFrame) -> str:
    with st.sidebar:
        st.markdown(
            """
            <div class="sidebar-brand">
                <div class="sidebar-logo">RG</div>
                <div class="sidebar-brand-copy">
                    <div class="sidebar-kicker">AI Security Ops</div>
                    <div class="sidebar-title">RAG Guard Copilot</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            "<div class='sidebar-inline-note'>Secure RAG / AI governance / Demo data</div>",
            unsafe_allow_html=True,
        )

        st.markdown("<div class='sidebar-section'>Navigation</div>", unsafe_allow_html=True)
        page_name = st.radio("Navigate", PAGE_OPTIONS, key="page_name", label_visibility="collapsed")

        current_user = users_df.set_index("user_id").loc[st.session_state["selected_user_id"]]
        st.markdown("<div class='sidebar-section'>Current operator</div>", unsafe_allow_html=True)
        st.markdown(
            f"""
            <div class="sidebar-note">
                <div class="sidebar-operator-row">
                    <div class="sidebar-avatar">{escape_markup(initials_for_name(str(current_user['name'])))}</div>
                    <div>
                        <div class="sidebar-operator-name">{escape_markup(current_user['name'])}</div>
                        <div class="sidebar-operator-meta">{escape_markup(current_user['department'])} / {escape_markup(current_user['role'])}</div>
                    </div>
                </div>
                <div class="sidebar-operator-groups">{escape_markup(", ".join(parse_allowed_groups(current_user['allowed_groups'])))}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            """
            <div class="sidebar-footnote">
                Local TF-IDF retrieval, prompt-injection blocking, and audit evidence stay deterministic for demo runs.
            </div>
            """,
            unsafe_allow_html=True,
        )

    return page_name


def render_workspace_page(users_df: pd.DataFrame, documents_df: pd.DataFrame, audit_view: pd.DataFrame) -> None:
    render_page_header(
        "Secure RAG operations",
        "Secure Workspace",
        "Operate the secure retrieval workflow over sensitive enterprise and autonomous logistics knowledge with visible policy decisions.",
        [],
    )

    result = st.session_state.get("last_result")
    if result:
        render_stat_cards(
            [
                ("Allowed documents", str(len(result.allowed_docs)), "Context cleared for grounded answers"),
                ("Blocked documents", str(len(result.blocked_docs)), "Denied or quarantined candidates"),
                ("Masked PII", str(result.masked_pii_count), "Sensitive values redacted before assembly"),
                ("Latency", f"{result.latency_ms} ms", "Observed local workflow runtime"),
            ]
        )
    else:
        render_stat_cards(compute_observability_metrics(audit_view))

    left, right = st.columns([1.45, 1])
    with left:
        with st.container(border=True):
            st.markdown("#### Query control center")
            st.markdown(
                "Compose a request, adjust retrieval depth, or trigger a curated workflow that highlights security decisions."
            )
            button_cols = st.columns(len(SCENARIOS))
            for column, scenario in zip(button_cols, SCENARIOS, strict=True):
                if column.button(scenario["cta"], key=f"workspace_{scenario['id']}", width="stretch"):
                    run_query_and_refresh(
                        scenario["user_id"],
                        scenario["query"],
                        st.session_state["retrieval_depth"],
                        scenario_id=scenario["id"],
                        sync_inputs=True,
                    )

            with st.form("workspace_query_form"):
                st.selectbox(
                    "Role / identity",
                    options=users_df["user_id"].tolist(),
                    key="selected_user_id",
                    format_func=lambda user_id: format_user_label(user_id, users_df),
                )
                st.slider(
                    "Retrieval depth",
                    min_value=3,
                    max_value=max(3, len(documents_df)),
                    key="retrieval_depth",
                    help="Control how many candidate documents enter the policy and security review path.",
                )
                st.text_area(
                    "Question or operational prompt",
                    key="query_text",
                    height=160,
                    help="Use realistic enterprise prompts. This app evaluates the same backend pipeline used by the CLI and tests.",
                )
                submit_col, reset_col = st.columns(2)
                submitted = submit_col.form_submit_button(
                    "Run secure retrieval",
                    type="primary",
                    width="stretch",
                )
                reset_requested = reset_col.form_submit_button("Reset composer", width="stretch")

            if reset_requested:
                st.session_state["selected_user_id"] = users_df.iloc[0]["user_id"]
                st.session_state["query_text"] = DEFAULT_QUERY
                st.session_state["retrieval_depth"] = 5
                st.rerun()

            if submitted:
                if st.session_state["query_text"].strip():
                    run_query_and_refresh(
                        st.session_state["selected_user_id"],
                        st.session_state["query_text"],
                        st.session_state["retrieval_depth"],
                    )
                st.warning("Enter a prompt before running the secure workflow.")

    with right:
        with st.container(border=True):
            selected_user = users_df.set_index("user_id").loc[st.session_state["selected_user_id"]]
            render_identity_panel(selected_user)
        with st.container(border=True):
            st.markdown("#### Guardrail stance")
            st.markdown(
                """
                This workspace highlights actual backend controls:

                - retrieval is ranked locally, then filtered by identity and group policy
                - retrieved content is treated as untrusted input and scanned for injection patterns
                - allowed context is masked before the answer is assembled
                - every run writes audit evidence that can be inspected in the ledger
                """
            )

    if not result:
        with st.container(border=True):
            st.info("Run a secure workflow to inspect grounded answers, blocked context, trace events, and observability signals.")
        return

    answer_tab, retrieval_tab, pii_tab, trace_tab = st.tabs(
        ["Assistant Output", "Retrieval Panels", "PII Masking", "Security Trace"]
    )

    with answer_tab:
        answer_left, answer_right = st.columns([1.25, 1])
        with answer_left:
            with st.container(border=True):
                render_answer_panel(result)
        with answer_right:
            with st.container(border=True):
                render_decision_summary(result)

    with retrieval_tab:
        allowed_col, blocked_col = st.columns(2)
        with allowed_col:
            with st.container(border=True):
                st.markdown("#### Allowed context")
                allowed_df = result_doc_table(result.allowed_docs)
                if allowed_df.empty:
                    st.info("No documents cleared the secure retrieval path for this run.")
                else:
                    st.dataframe(allowed_df, width="stretch", hide_index=True)
        with blocked_col:
            with st.container(border=True):
                st.markdown("#### Blocked context")
                blocked_df = result_doc_table(result.blocked_docs)
                if blocked_df.empty:
                    st.success("No documents were blocked in this run.")
                else:
                    st.dataframe(blocked_df, width="stretch", hide_index=True)

        with st.container(border=True):
            st.markdown("#### Candidate ledger")
            st.dataframe(result_to_rows(result), width="stretch", hide_index=True)

    with pii_tab:
        with st.container(border=True):
            st.markdown("#### Masking demo")
            render_masking_demo(result, documents_df)

    with trace_tab:
        event_col, trace_col = st.columns([1.05, 1])
        with event_col:
            with st.container(border=True):
                st.markdown("#### Security events")
                render_security_event_cards(result)
        with trace_col:
            with st.container(border=True):
                st.markdown("#### Trace steps")
                render_trace_steps(result)


def render_decision_explorer_page(documents_df: pd.DataFrame) -> None:
    render_page_header(
        "Policy and retrieval review",
        "Decision Explorer",
        "Inspect every retrieved candidate, the final decision reason, and the controls that shaped the answer path.",
        [],
    )

    result = st.session_state.get("last_result")
    if not result:
        with st.container(border=True):
            st.info("Run a workflow in Secure Workspace first to populate the decision explorer.")
        return

    render_stat_cards(
        [
            ("Candidates reviewed", str(len(result.retrieval_decisions)), "Retrieved documents inspected by the pipeline"),
            ("Allowed path", str(len(result.allowed_docs)), "Candidates kept for grounded answer assembly"),
            ("Guardrail interventions", str(len(result.blocked_docs)), "Access denials and malicious context quarantines"),
            ("Security events", str(len(result.security_events)), "Access, masking, and injection events raised"),
        ]
    )

    ledger_tab, explanation_tab, context_tab = st.tabs(
        ["Candidate Ledger", "Explanation Deck", "Context Review"]
    )

    with ledger_tab:
        with st.container(border=True):
            st.markdown("#### Candidate ledger")
            st.dataframe(result_to_rows(result), width="stretch", hide_index=True)

    with explanation_tab:
        interventions_only = st.toggle(
            "Only show guardrail interventions",
            value=False,
            key="decision_interventions_only",
        )
        with st.container(border=True):
            st.markdown("#### Retrieval decision explanations")
            render_candidate_explainers(result, documents_df, interventions_only=interventions_only)

    with context_tab:
        documents_lookup = documents_df.set_index("doc_id")
        allowed_col, blocked_col = st.columns(2)
        with allowed_col:
            with st.container(border=True):
                st.markdown("#### Allowed context review")
                if not result.allowed_docs:
                    st.info("No allowed context is available for this run.")
                for doc in result.allowed_docs:
                    preview = documents_lookup.loc[doc.doc_id]["content"]
                    with st.expander(f"{doc.title} | {doc.group}", expanded=False):
                        st.markdown(f"**Decision**: {doc.access_reason}")
                        st.code(str(preview), language="text")
        with blocked_col:
            with st.container(border=True):
                st.markdown("#### Blocked context review")
                if not result.blocked_docs:
                    st.success("No blocked context is available for this run.")
                for doc in result.blocked_docs:
                    preview = documents_lookup.loc[doc.doc_id]["content"]
                    with st.expander(f"{doc.title} | {doc.group}", expanded=False):
                        st.markdown(f"**Decision**: {doc.access_reason}")
                        st.code(str(preview), language="text")


def render_audit_trail_page(users_df: pd.DataFrame, audit_view: pd.DataFrame) -> None:
    render_page_header(
        "Observability and governance",
        "Audit Trail",
        "Review the persistent evidence generated by the secure RAG workflow, including blocked requests, latency, and masking activity.",
        [],
    )

    if audit_view.empty:
        with st.container(border=True):
            st.info("No audit events exist yet. Run a secure workflow to populate the ledger.")
        return

    with st.container(border=True):
        filter_cols = st.columns(4)
        user_filter = filter_cols[0].selectbox(
            "Identity filter",
            options=["All identities", *users_df["user_id"].tolist()],
            format_func=lambda value: value if value == "All identities" else format_user_label(value, users_df),
            key="audit_user_filter",
        )
        blocked_only = filter_cols[1].toggle("Blocked requests only", value=False, key="audit_blocked_only")
        injection_only = filter_cols[2].toggle("Injection flags only", value=False, key="audit_injection_only")
        row_limit = filter_cols[3].selectbox("Rows to show", options=[10, 25, 50, 100], index=1, key="audit_row_limit")

    filtered = audit_view.copy()
    if user_filter != "All identities":
        filtered = filtered[filtered["user_id"] == user_filter]
    if blocked_only:
        filtered = filtered[filtered["blocked_count"] > 0]
    if injection_only:
        filtered = filtered[filtered["injection_count"] > 0]

    render_stat_cards(compute_observability_metrics(filtered if not filtered.empty else audit_view))

    ledger_tab, observability_tab, latest_tab = st.tabs(["Audit Ledger", "Observability", "Latest Session"])

    with ledger_tab:
        with st.container(border=True):
            st.markdown("#### Audit ledger")
            st.download_button(
                "Export filtered audit CSV",
                data=filtered.to_csv(index=False).encode("utf-8"),
                file_name="rag_guard_copilot_audit.csv",
                mime="text/csv",
                width="content",
            )
            if filtered.empty:
                st.info("No audit rows match the current filters.")
            else:
                display_columns = [
                    "timestamp_label",
                    "user_id",
                    "department",
                    "role",
                    "query",
                    "allowed_count",
                    "blocked_count",
                    "injection_count",
                    "masked_pii_count",
                    "latency_ms",
                ]
                st.dataframe(
                    filtered.head(row_limit)[display_columns],
                    width="stretch",
                    hide_index=True,
                )
                for row in filtered.head(min(row_limit, 8)).to_dict(orient="records"):
                    summary = f"{row['timestamp_label']} | {row['user_id']} | {row['query']}"
                    with st.expander(summary, expanded=False):
                        blocked_reasons = row["blocked_reason_map"]
                        if blocked_reasons:
                            st.markdown("**Blocked reasons**")
                            st.json(blocked_reasons)
                        st.markdown("**Allowed docs**")
                        st.write(", ".join(row["allowed_doc_ids"]) or "None")
                        st.markdown("**Blocked docs**")
                        st.write(", ".join(row["blocked_doc_ids"]) or "None")

    with observability_tab:
        chart_source = (filtered if not filtered.empty else audit_view).sort_values("timestamp")
        trend_col, mix_col = st.columns(2)
        with trend_col:
            with st.container(border=True):
                st.markdown("#### Latency by recent run")
                latency_table = chart_source[["timestamp_label", "user_id", "latency_ms"]].tail(12)
                st.dataframe(latency_table, width="stretch", hide_index=True)
        with mix_col:
            with st.container(border=True):
                st.markdown("#### Outcome mix by recent run")
                outcome_table = chart_source[
                    ["timestamp_label", "allowed_count", "blocked_count", "masked_pii_count"]
                ].tail(12)
                st.dataframe(outcome_table, width="stretch", hide_index=True)

        with st.container(border=True):
            st.markdown("#### Identity-level summary")
            user_summary = (
                chart_source.groupby(["user_id", "department", "role"], dropna=False)
                .agg(
                    requests=("query", "count"),
                    avg_allowed_docs=("allowed_count", "mean"),
                    avg_blocked_docs=("blocked_count", "mean"),
                    avg_latency_ms=("latency_ms", "mean"),
                    masked_pii=("masked_pii_count", "sum"),
                )
                .reset_index()
            )
            st.dataframe(user_summary, width="stretch", hide_index=True)

    with latest_tab:
        latest_result = st.session_state.get("last_result")
        if not latest_result:
            st.info("Run a secure workflow to inspect the latest session trace.")
        else:
            session_left, session_right = st.columns([1.1, 1])
            with session_left:
                with st.container(border=True):
                    st.markdown("#### Latest session summary")
                    render_decision_summary(latest_result)
            with session_right:
                with st.container(border=True):
                    st.markdown("#### Latest session events")
                    render_security_event_cards(latest_result)


def render_scenario_lab_page(users_df: pd.DataFrame, documents_df: pd.DataFrame) -> None:
    render_page_header(
        "Controlled demo workflows",
        "Scenario Lab",
        "Run curated test cases for access denial, injection defense, masking, and regression coverage using demo/sample data.",
        [],
    )

    scenario_lookup = {scenario["id"]: scenario for scenario in SCENARIOS}
    selected_scenario_id = st.selectbox(
        "Scenario",
        options=[scenario["id"] for scenario in SCENARIOS],
        format_func=lambda scenario_id: scenario_lookup[scenario_id]["title"],
        key="lab_scenario_id",
    )
    selected_scenario = scenario_lookup[selected_scenario_id]

    top_left, top_right = st.columns([1.25, 1])
    with top_left:
        with st.container(border=True):
            st.markdown("#### Scenario brief")
            st.markdown(selected_scenario["description"])
            st.markdown(f"**User**: {format_user_label(selected_scenario['user_id'], users_df)}")
            st.markdown(f"**Prompt**: `{selected_scenario['query']}`")
            st.markdown(f"**Expected signal**: `{selected_scenario['expected']}`")
            run_col, suite_col = st.columns(2)
            if run_col.button("Run selected scenario", type="primary", width="stretch"):
                run_query_and_refresh(
                    selected_scenario["user_id"],
                    selected_scenario["query"],
                    st.session_state["retrieval_depth"],
                    scenario_id=selected_scenario_id,
                    sync_inputs=True,
                )
            if suite_col.button("Run regression suite", width="stretch"):
                with st.spinner("Running curated security scenarios..."):
                    st.session_state["regression_rows"] = run_regression_suite()
                st.rerun()

    with top_right:
        with st.container(border=True):
            scenario_user = users_df.set_index("user_id").loc[selected_scenario["user_id"]]
            render_identity_panel(scenario_user)

    scenario_tab, regression_tab, sample_tab = st.tabs(
        ["Scenario Result", "Regression Matrix", "Sample Data"]
    )

    with scenario_tab:
        lab_result = st.session_state.get("lab_result")
        if not lab_result:
            with st.container(border=True):
                st.info("Run a curated scenario to populate this view.")
        else:
            last_scenario_id = st.session_state.get("last_scenario_id")
            if last_scenario_id and last_scenario_id != selected_scenario_id:
                last_title = scenario_lookup[last_scenario_id]["title"]
                st.caption(f"Showing the most recently executed scenario result: {last_title}.")
            render_stat_cards(
                [
                    ("Allowed docs", str(len(lab_result.allowed_docs)), "Documents that stayed on the grounded answer path"),
                    ("Blocked docs", str(len(lab_result.blocked_docs)), "Documents denied by policy or guardrails"),
                    ("Security events", str(len(lab_result.security_events)), "Events raised for the scenario"),
                    ("Latency", f"{lab_result.latency_ms} ms", "Local workflow runtime"),
                ]
            )
            summary_col, events_col = st.columns([1.15, 1])
            with summary_col:
                with st.container(border=True):
                    render_answer_panel(lab_result)
            with events_col:
                with st.container(border=True):
                    render_security_event_cards(lab_result)

    with regression_tab:
        rows = st.session_state.get("regression_rows", [])
        if not rows:
            with st.container(border=True):
                st.info("Run the regression suite to capture pass/fail coverage for the curated scenarios.")
        else:
            regression_df = pd.DataFrame(rows)
            pass_rate = regression_df["passed"].mean()
            render_stat_cards(
                [
                    ("Suite pass rate", f"{pass_rate:.0%}", "Curated scenario expectations"),
                    ("Scenarios", str(len(regression_df)), "Regression scenarios executed"),
                    ("Failures", str(int((~regression_df['passed']).sum())), "Scenarios that missed their expected signal"),
                ]
            )
            with st.container(border=True):
                st.markdown("#### Regression matrix")
                st.dataframe(regression_df, width="stretch", hide_index=True)

    with sample_tab:
        sample_left, sample_right = st.columns(2)
        with sample_left:
            with st.container(border=True):
                st.markdown("#### Sample identities")
                st.caption("Demo/sample data")
                st.dataframe(
                    users_df[["user_id", "name", "department", "role", "allowed_groups"]],
                    width="stretch",
                    hide_index=True,
                )
        with sample_right:
            with st.container(border=True):
                st.markdown("#### Sample documents")
                st.caption("Demo/sample data")
                st.dataframe(
                    documents_df[["doc_id", "title", "group", "sensitivity"]],
                    width="stretch",
                    hide_index=True,
                )


def main() -> None:
    users_df = get_users()
    documents_df = get_documents()
    init_session_state(users_df)
    inject_styles()

    audit_view = build_audit_view(load_audit_log())
    page_name = render_sidebar(users_df, documents_df)

    if page_name == "Secure Workspace":
        render_workspace_page(users_df, documents_df, audit_view)
    elif page_name == "Decision Explorer":
        render_decision_explorer_page(documents_df)
    elif page_name == "Audit Trail":
        render_audit_trail_page(users_df, audit_view)
    else:
        render_scenario_lab_page(users_df, documents_df)


if __name__ == "__main__":
    main()
