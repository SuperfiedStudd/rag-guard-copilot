# RAG Guard Copilot

RAG Guard Copilot proves a specific engineering point: a retrieval system can enforce identity-aware access control, filter prompt-injection content, mask sensitive data, and emit audit evidence before any LLM answer is assembled.

This repo is backend-first. The core deliverable is a testable secure RAG pipeline under `src/rag_guard_copilot/`. Streamlit is included as a thin demo surface for inspection, not as the product itself.

## What this project proves

- retrieval can be policy-aware instead of blindly relevance-first
- unsafe retrieved context can be blocked before answer construction
- prompt-injection defense belongs in the retrieval pipeline, not only at the model boundary
- PII masking and audit logging can be first-class pipeline steps
- the same security engine can be exercised through tests, CLI, and UI

## Core capabilities

- Simulates identity metadata with mock users, departments, roles, and allowed document groups
- Retrieves candidate documents with local TF-IDF search
- Applies per-document access decisions before prompt context is built
- Detects prompt-injection phrases in retrieved content and blocks flagged documents
- Masks emails, phone numbers, SSNs, salaries, and street addresses before answer assembly
- Writes audit records with user, query, allowed docs, blocked docs, injection flags, masked PII count, token estimate, and latency
- Exposes the pipeline through both a CLI and a Streamlit review UI

## Why this is not just a dashboard

- The main logic lives in typed backend modules, not in the UI layer.
- The secure flow is executable without Streamlit through `python -m rag_guard_copilot.cli`.
- Tests validate the backend pipeline directly, including blocked retrieval, injection detection, PII masking, and audit writes.
- Streamlit is only a reviewer-friendly lens over the same pipeline used by the CLI and tests.

## Architecture

```text
rag-guard-copilot/
|-- app.py
|-- pyproject.toml
|-- requirements.txt
|-- README.md
|-- demo_scenarios.md
|-- docs/
|   `-- threat_model.md
|-- sample_data/
|   |-- documents.csv
|   `-- users.csv
`-- src/
    `-- rag_guard_copilot/
        |-- assistant.py
        |-- audit.py
        |-- cli.py
        |-- config.py
        |-- data_loader.py
        |-- pipeline.py
        |-- policy_engine.py
        |-- retrieval.py
        |-- schemas.py
        `-- security.py
```

## Run locally

1. Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install the project:

```powershell
python -m pip install -e .
```

Dependency ownership lives in `pyproject.toml`. The `requirements.txt` file is intentionally minimal and kept as a deployment shim for platforms that expect it.

3. Run the backend pipeline directly:

```powershell
python -m rag_guard_copilot.cli --user finance_analyst --query "show finance vendor risk"
```

4. Optionally launch the demo UI:

```powershell
python -m streamlit run app.py
```

## Enterprise AI Security Alignment

- Identity-aware retrieval: access control is enforced at document-selection time, not only after generation.
- RAG security: retrieved context is treated as untrusted input and screened before prompt assembly.
- AI governance: the pipeline produces explicit decision artifacts such as deny reasons, masked PII counts, and audit rows.
- Prompt-injection defense: malicious retrieved instructions are flagged and blocked from the answer path.
- PII masking: common high-risk patterns are redacted before context is passed forward.
- Audit logging: every run captures structured evidence useful for review, debugging, and control validation.
- LLM observability: token estimate, latency estimate, retrieval outcomes, and security events are surfaced as pipeline outputs.

## Honest scope

What is real in this repo:

- backend-first secure RAG orchestration
- typed policy and pipeline modules
- local retrieval
- deterministic test coverage
- CLI and UI access to the same engine

What is intentionally mocked or simplified:

- identity provider integration
- production policy engines
- semantic prompt-injection classification
- production-grade PII detection coverage
- external model integration
- SIEM, retention, and enterprise logging controls

This is a credible engineering demo, not a claim of production completeness.

## Review path

For a fast technical review:

1. Read [src/rag_guard_copilot/pipeline.py](/D:/rag-guard-copilot/src/rag_guard_copilot/pipeline.py)
2. Inspect [src/rag_guard_copilot/policy_engine.py](/D:/rag-guard-copilot/src/rag_guard_copilot/policy_engine.py) and [src/rag_guard_copilot/security.py](/D:/rag-guard-copilot/src/rag_guard_copilot/security.py)
3. Run the CLI scenario
4. Check [tests/test_security_pipeline.py](/D:/rag-guard-copilot/tests/test_security_pipeline.py)
5. Use Streamlit only to inspect decisions visually

## Next improvements

1. Replace TF-IDF with local embeddings and chunk-level retrieval.
2. Add row-level and attribute-level policy enforcement.
3. Expand prompt-injection detection beyond rule patterns.
4. Add stronger audit controls such as retention policy and tamper-evident export.
5. Add optional model integration behind a feature flag with hardened prompt construction.
