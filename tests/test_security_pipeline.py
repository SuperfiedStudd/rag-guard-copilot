from pathlib import Path

from rag_guard_copilot.audit import load_audit_log
from rag_guard_copilot.pipeline import run_secure_pipeline
from rag_guard_copilot.security import mask_pii


def test_unauthorized_docs_are_blocked():
    result = run_secure_pipeline("Show the merger risk memo.", "u_hr_01")

    blocked_ids = {doc.doc_id for doc in result.blocked_docs}
    assert "doc_legal_01" in blocked_ids


def test_prompt_injection_docs_are_flagged():
    result = run_secure_pipeline("Any security runbook updates?", "u_it_01")

    flagged_ids = {event.doc_id for event in result.security_events if event.type == "prompt_injection_flag"}
    assert "doc_sec_01" in flagged_ids


def test_pii_is_masked():
    sample = (
        "Contact maya.patel@corp.example at 415-555-0188, SSN 123-45-6789, "
        "salary $145,000 annual, address 2211 Market Street."
    )

    masked, counts = mask_pii(sample)

    assert "[EMAIL_REDACTED]" in masked
    assert "[PHONE_REDACTED]" in masked
    assert "[SSN_REDACTED]" in masked
    assert "[SALARY_REDACTED]" in masked
    assert "[ADDRESS_REDACTED]" in masked
    assert counts == {"email": 1, "phone": 1, "ssn": 1, "salary": 1, "address": 1}


def test_audit_rows_are_written(tmp_path, monkeypatch):
    import rag_guard_copilot.audit as audit_module

    monkeypatch.setattr(audit_module, "LOG_DIR", Path(tmp_path))

    run_secure_pipeline("What happened in the Q3 finance plan?", "finance_analyst")

    audit_df = load_audit_log()

    assert len(audit_df) == 1
    assert audit_df.iloc[0]["user_id"] == "u_fin_01"
    assert audit_df.iloc[0]["query"] == "What happened in the Q3 finance plan?"
