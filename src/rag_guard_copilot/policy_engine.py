from __future__ import annotations

from .schemas import Document, User


def evaluate_access(user: User, document: Document) -> tuple[bool, str]:
    normalized_group = document.group.strip().lower()
    if normalized_group == "public":
        return True, "Public document is available to all users."

    if normalized_group in user.allowed_groups:
        return True, f"User has explicit access to the '{normalized_group}' document group."

    if normalized_group == "internal" and user.role.lower() in {"manager", "director", "counsel"}:
        return True, f"Role '{user.role}' is allowed to view internal documents."

    return False, f"User is not permitted to access the '{normalized_group}' document group."
