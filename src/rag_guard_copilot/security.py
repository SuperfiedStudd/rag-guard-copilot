from __future__ import annotations

import re
from dataclasses import dataclass

import pandas as pd


GROUP_ACCESS = {
    "public": {"public"},
    "internal": {"internal", "finance", "hr", "legal"},
    "finance": {"finance"},
    "hr": {"hr"},
    "legal": {"legal"},
}

INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior) instructions",
    r"ignore permissions",
    r"reveal secrets",
    r"bypass (security|guardrails|filters)",
    r"system prompt",
    r"developer message",
    r"exfiltrate",
    r"override policy",
]

PII_PATTERNS = {
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "phone": re.compile(r"\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "salary": re.compile(r"\$\d[\d,]*(?:\.\d{2})?(?:\s*(?:annual|yearly|per year))?", re.IGNORECASE),
    "address": re.compile(
        r"\b\d{2,5}\s+[A-Za-z0-9.\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\b",
        re.IGNORECASE,
    ),
}


@dataclass
class AccessDecision:
    allowed: bool
    reason: str


def parse_allowed_groups(raw_value: str) -> set[str]:
    return {item.strip().lower() for item in raw_value.split("|") if item.strip()}


def get_user_record(users_df: pd.DataFrame, user_id: str) -> dict:
    user = users_df.loc[users_df["user_id"] == user_id]
    if user.empty:
        raise ValueError(f"Unknown user_id: {user_id}")
    record = user.iloc[0].to_dict()
    record["allowed_groups"] = parse_allowed_groups(str(record["allowed_groups"]))
    return record


def check_document_access(user: dict, document_group: str) -> AccessDecision:
    normalized_group = document_group.strip().lower()
    if normalized_group == "public":
        return AccessDecision(True, "Public document is available to all users.")

    if normalized_group in user["allowed_groups"]:
        return AccessDecision(True, f"User has explicit access to the '{normalized_group}' document group.")

    if normalized_group == "internal" and user["role"].lower() in {"manager", "director", "counsel"}:
        return AccessDecision(True, f"Role '{user['role']}' is allowed to view internal documents.")

    return AccessDecision(False, f"User is not permitted to access the '{normalized_group}' document group.")


def detect_prompt_injection(text: str) -> list[str]:
    lowered = text.lower()
    findings: list[str] = []
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, lowered):
            findings.append(pattern)
    return findings


def mask_pii(text: str) -> tuple[str, dict[str, int]]:
    masked_text = text
    pii_counts: dict[str, int] = {}
    replacements = {
        "email": "[EMAIL_REDACTED]",
        "phone": "[PHONE_REDACTED]",
        "ssn": "[SSN_REDACTED]",
        "salary": "[SALARY_REDACTED]",
        "address": "[ADDRESS_REDACTED]",
    }
    for label, pattern in PII_PATTERNS.items():
        matches = pattern.findall(masked_text)
        if matches:
            pii_counts[label] = len(matches)
            masked_text = pattern.sub(replacements[label], masked_text)
    return masked_text, pii_counts
