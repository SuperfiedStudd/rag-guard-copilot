# Threat Model

## Scope

This demo models a policy-aware RAG security pipeline for internal autonomous logistics assistants. The main security goal is to prevent unsafe route, safety, customer, maintenance, or compliance context from reaching answer construction while preserving useful access for approved roles.

## Prompt injection

Threat:

- Retrieved notes contain malicious instructions such as `ignore previous instructions`, `override policy`, or requests to reveal restricted operator or contract details.

Risk:

- The assistant could treat hostile retrieved content as instructions instead of data.

Current mitigation:

- Retrieved content is screened for injection-style patterns before it is admitted into prompt context.
- Flagged documents are blocked from the answer path and recorded as security events.

Remaining gap:

- Pattern matching is intentionally simple and should be upgraded for more robust semantic detection in production.

## Unauthorized retrieval

Threat:

- Users attempt to retrieve content outside their allowed route-operations, safety, customer, maintenance, or compliance bands.

Risk:

- Sensitive operational knowledge could leak through retrieval before generation controls apply.

Current mitigation:

- Access policy is enforced per retrieved document by the backend policy engine.
- Denied documents are excluded from context and include human-readable deny reasons.
- Evaluation scenarios and tests cover blocked retrieval, partial retrieval, and vendor overaccess behavior.

Remaining gap:

- The demo uses coarse document-group controls rather than row-level, attribute-level, or external policy-provider enforcement.

## PII leakage

Threat:

- Retrieved operational documents contain emails, phone numbers, SSNs, salary data, or addresses.

Risk:

- Sensitive personal or contact data could be passed into prompts, logs, or model outputs.

Current mitigation:

- PII patterns are masked before prompt construction.
- Masking counts are surfaced in the audit trail and UI.

Remaining gap:

- Regex masking is suitable for demo scope but not sufficient for full production coverage across jurisdictions and edge cases.

## Audit and logging abuse

Threat:

- Audit logs may themselves become a source of sensitive operational data or may be spammed by repeated requests.

Risk:

- Logs could expose usage patterns, blocked-document IDs, or become noisy enough to reduce their governance value.

Current mitigation:

- The audit trail is structured and records only decision metadata needed for the demo.
- The pipeline stores blocked and allowed document IDs rather than full document bodies.

Remaining gap:

- The demo does not yet add log retention controls, integrity checks, tamper evidence, or rate limiting.

## Shadow AI risks

Threat:

- Employees use ungoverned AI workflows outside approved enterprise controls.

Risk:

- Sensitive route, safety, customer, or fleet knowledge may be retrieved or shared without access checks, masking, or auditability.

Current mitigation:

- This project demonstrates how a governed assistant can centralize retrieval policy, prompt defense, redaction, and audit logging in one backend pipeline.

Remaining gap:

- The repo is a local demo and does not enforce organization-wide adoption, network controls, or vendor governance policies.
