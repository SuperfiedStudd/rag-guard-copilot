# RAG Guard Copilot

RAG Guard Copilot is a demo-ready portfolio project that shows identity-aware RAG security for enterprise AI assistants. It simulates user-level access control, blocks unsafe retrieval, detects prompt injection in retrieved documents, masks sensitive data before prompt construction, and logs every query in a simple audit trail.

The real product in this repo is the policy-aware RAG security pipeline under `src/rag_guard_copilot/`. Streamlit is a thin demo UI over that backend so reviewers can inspect the same engine visually.

## Why this project is strong for JD alignment

This repo is intentionally shaped for security, AI platform, and applied ML roles that ask for:

- secure AI application design
- RAG and retrieval controls
- prompt injection awareness
- privacy and data protection practices
- developer-facing demos with clear observability

The demo emphasizes practical guardrails over model novelty. It shows how an assistant can remain helpful while respecting access policy and reducing common enterprise AI risks.

## What the app does

- Simulates Google/Okta-style identity metadata with mock users, departments, roles, and allowed document groups
- Retrieves candidate documents with local TF-IDF search
- Applies per-document access checks before context assembly
- Detects prompt-injection phrases in retrieved content and blocks those documents from prompt context
- Masks emails, phone numbers, SSNs, salaries, and street addresses
- Writes an audit log with user, query, allowed docs, blocked docs, flagged injections, masked PII count, token estimate, and latency
- Provides a Streamlit dashboard with `Query Assistant`, `Access Audit`, `Security Events`, and `Evaluation` tabs
- Exposes a backend-first security pipeline and CLI for non-UI testing and scenario execution

## Project structure

```text
rag-guard-copilot/
|-- app.py
|-- requirements.txt
|-- README.md
|-- AGENTS.md
|-- PROJECT_CONTEXT.md
|-- RULES.md
|-- TASK_LOG.md
|-- sample_data/
|   |-- documents.csv
|   `-- users.csv
`-- src/
    `-- rag_guard_copilot/
        |-- __init__.py
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

2. Install dependencies:

```powershell
python -m pip install -e .
```

Dependency ownership lives in `pyproject.toml`. The `requirements.txt` file is kept as a thin deployment shim for environments like Streamlit that expect it.

3. Start the app:

```powershell
python -m streamlit run app.py
```

4. Open the local Streamlit URL shown in the terminal.

## Backend-first usage

Run the security engine directly without Streamlit:

```powershell
python -m rag_guard_copilot.cli --user finance_analyst --query "show finance vendor risk"
```

The CLI prints allowed documents, blocked documents, injection flags, masked PII count, and the audit event path for the run.

If you prefer a pinned dependency snapshot for non-editable environments, `requirements.txt` is still included.

## Demo notes

- No paid API is required.
- Optional LLM calling is intentionally disabled by default.
- Retrieval is local and lightweight for easy demo portability.
- Audit logs are written to `logs/audit_log.csv` after queries run.
- Streamlit is demo UI only; the core logic lives in the backend pipeline modules.

## Current behavior

### Works now

- mock identity and access simulation
- secure retrieval with allowed vs blocked reasoning
- prompt injection detection on malicious sample docs
- PII masking before response context is assembled
- audit logging and security event surfacing
- basic evaluation scenarios in the UI
- CLI execution of the same security engine without Streamlit

### Mocked

- identity provider integration
- production document store and chunking pipeline
- real LLM response generation
- enterprise auth, policy engines, and SIEM export

## How this maps to AI Operations & RAG Architect work

- Shows how retrieval systems can enforce identity-aware access policy before context reaches a model.
- Demonstrates practical defense-in-depth for enterprise assistants through access control, prompt-injection screening, PII redaction, and auditability.
- Mirrors AI operations concerns such as observability, safety checks, deterministic evaluations, and local-first demo environments that are easy to validate.
- Provides a portfolio-friendly example of secure RAG orchestration without hiding behind paid APIs or overbuilt infrastructure.

## Next improvements

1. Swap TF-IDF for embeddings with a local sentence-transformer.
2. Add row-level and attribute-level policy checks.
3. Add downloadable audit evidence packs and JSON exports.
4. Connect to a real model behind a feature flag with prompt hardening.
5. Add automated regression tests for access, injection, and masking rules.
