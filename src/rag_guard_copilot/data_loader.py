from __future__ import annotations

from functools import lru_cache

import pandas as pd

from .config import DATA_DIR
from .schemas import Document, User
from .security import parse_allowed_groups


@lru_cache(maxsize=1)
def load_users() -> pd.DataFrame:
    return pd.read_csv(DATA_DIR / "users.csv")


@lru_cache(maxsize=1)
def load_documents() -> pd.DataFrame:
    return pd.read_csv(DATA_DIR / "documents.csv")


@lru_cache(maxsize=1)
def load_user_objects() -> list[User]:
    return [
        User(
            user_id=row["user_id"],
            name=row["name"],
            department=row["department"],
            role=row["role"],
            allowed_groups=parse_allowed_groups(str(row["allowed_groups"])),
        )
        for row in load_users().to_dict(orient="records")
    ]


@lru_cache(maxsize=1)
def load_document_objects() -> list[Document]:
    return [
        Document(
            doc_id=row["doc_id"],
            title=row["title"],
            group=row["group"],
            sensitivity=row["sensitivity"],
            content=row["content"],
        )
        for row in load_documents().to_dict(orient="records")
    ]


def resolve_user(user_ref: str, users: list[User]) -> User:
    normalized = user_ref.strip().lower()
    for user in users:
        if user.user_id.lower() == normalized or user.handle == normalized:
            return user
    raise ValueError(f"Unknown user reference: {user_ref}")


def get_document(doc_id: str, documents: list[Document]) -> Document:
    for document in documents:
        if document.doc_id == doc_id:
            return document
    raise ValueError(f"Unknown doc_id: {doc_id}")
