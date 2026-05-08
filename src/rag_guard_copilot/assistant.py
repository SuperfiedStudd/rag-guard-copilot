from __future__ import annotations

from .pipeline import run_secure_pipeline


def run_secure_query(query: str, user_id: str, users_df=None, documents_df=None) -> dict:
    del users_df, documents_df
    return run_secure_pipeline(query, user_id).to_legacy_dict()
