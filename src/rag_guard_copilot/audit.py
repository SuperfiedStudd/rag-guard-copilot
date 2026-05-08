from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pandas as pd

from .config import LOG_DIR


AUDIT_COLUMNS = [
    "timestamp",
    "user_id",
    "department",
    "role",
    "query",
    "allowed_docs",
    "blocked_docs",
    "blocked_reasons",
    "injection_doc_ids",
    "masked_pii_count",
    "token_estimate",
    "latency_ms",
    "llm_enabled",
]


def ensure_log_dir() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def append_audit_event(event: dict) -> Path:
    ensure_log_dir()
    audit_path = LOG_DIR / "audit_log.csv"
    row = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "user_id": event["user"]["user_id"],
        "department": event["user"]["department"],
        "role": event["user"]["role"],
        "query": event["query"],
        "allowed_docs": json.dumps(event["allowed_docs"]),
        "blocked_docs": json.dumps(event["blocked_docs"]),
        "blocked_reasons": json.dumps(event["blocked_reasons"]),
        "injection_doc_ids": json.dumps(event["injection_doc_ids"]),
        "masked_pii_count": event["masked_pii_count"],
        "token_estimate": event["token_estimate"],
        "latency_ms": event["latency_ms"],
        "llm_enabled": event["llm_enabled"],
    }
    frame = pd.DataFrame([row], columns=AUDIT_COLUMNS)
    if audit_path.exists():
        frame.to_csv(audit_path, mode="a", header=False, index=False)
    else:
        frame.to_csv(audit_path, index=False)
    return audit_path


def load_audit_log() -> pd.DataFrame:
    audit_path = LOG_DIR / "audit_log.csv"
    if not audit_path.exists():
        return pd.DataFrame(columns=AUDIT_COLUMNS)
    return pd.read_csv(audit_path)
