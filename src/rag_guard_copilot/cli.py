from __future__ import annotations

import argparse

from .pipeline import run_secure_pipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run policy-aware RAG security scenarios from the command line.")
    parser.add_argument("--user", required=True, help="User ID or handle such as 'u_fin_01' or 'finance_analyst'.")
    parser.add_argument("--query", required=True, help="Query to evaluate through the secure RAG pipeline.")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    result = run_secure_pipeline(args.query, args.user)

    print(f"user={result.user.user_id} ({result.user.handle})")
    print(f"query={result.query}")
    print(f"allowed_docs={[doc.doc_id for doc in result.allowed_docs]}")
    print(f"blocked_docs={[doc.doc_id for doc in result.blocked_docs]}")
    print(f"injection_flags={result.injection_doc_ids}")
    print(f"masked_pii_count={result.masked_pii_count}")
    print(f"audit_event_path={result.audit_path}")


if __name__ == "__main__":
    main()
