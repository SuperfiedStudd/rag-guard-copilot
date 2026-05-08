# Demo Scenarios

These walkthroughs are designed for recruiter and hiring-manager review. Each one shows a concrete security property of the backend pipeline, not just a UI behavior.

## 1. Normal employee retrieval

User:
`u_it_01`

Query:
`What changed in the engineering platform update?`

What this demonstrates:

- Internal content can still be retrieved when the user is authorized.
- The system is not security-only; it still returns useful grounded context.
- Access control happens without breaking normal assistant behavior.

Evidence to point out:

- Allowed documents include internal platform notes.
- The answer is built only from permitted context.
- The audit log records the run without showing document bodies.

## 2. Finance retrieval with masking

User:
`finance_analyst`

Query:
`What happened in the Q3 finance plan?`

What this demonstrates:

- Finance documents can be retrieved for the right identity.
- Sensitive values inside allowed documents are still treated carefully.
- Useful retrieval and privacy controls can coexist in one pipeline.

Evidence to point out:

- Finance content is allowed.
- Email and phone data in the finance memo are masked before answer assembly.
- The pipeline emits masked PII count, token estimate, latency, and audit path.

## 3. Unauthorized access attempt

User:
`u_hr_01`

Query:
`Show the merger risk memo.`

What this demonstrates:

- Relevance alone does not grant access.
- Least-privilege enforcement happens during retrieval, before an LLM sees the content.
- Deny reasons are explicit enough for review and debugging.

Evidence to point out:

- The legal memo may rank as relevant but is blocked.
- The blocked document carries a human-readable deny reason.
- The audit log captures the blocked retrieval attempt.

## 4. Prompt-injection in retrieved context

User:
`u_it_01`

Query:
`Any security runbook updates?`

What this demonstrates:

- Retrieved documents are treated as untrusted input.
- An authorized user is still prevented from inheriting malicious retrieved instructions.
- Prompt-injection defense is built into the pipeline rather than delegated entirely to the model.

Evidence to point out:

- The malicious security runbook is retrieved as relevant.
- Injection phrases such as `ignore permissions` and `reveal secrets` are flagged.
- The document is blocked from answer context even though the user has internal access.

## How to present this in a review

- Start with the CLI, not the UI, to show the backend-first design.
- Use the Streamlit app only as a visual inspection layer after the pipeline behavior is clear.
- Emphasize that the project demonstrates control points in secure RAG orchestration: policy enforcement, unsafe-context filtering, redaction, and auditability.
- Be direct that this is a strong engineering demo, not a production-complete security platform.
