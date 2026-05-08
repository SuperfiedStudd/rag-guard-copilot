# Demo Scenarios

## 1. Normal employee query

User: `u_it_01`  
Question: `What changed in the engineering platform update?`

What to show:

- The assistant retrieves internal platform notes.
- Public or internal content is allowed because the user has internal access.
- The answer uses only safe, permitted context.

Why recruiters care:

- Shows basic identity-aware retrieval without complexity.
- Demonstrates that normal users still get useful answers after security checks.

## 2. Finance user query

User: `u_fin_01`  
Question: `What happened in the Q3 finance plan?`

What to show:

- Finance content is retrieved and allowed.
- Email and phone details inside the finance memo are masked before prompt construction.
- The audit row captures allowed docs, masked PII count, token estimate, and latency.

Why recruiters care:

- Proves security controls can coexist with useful business retrieval.
- Highlights privacy-aware prompt assembly for sensitive enterprise data.

## 3. Unauthorized HR access attempt

User: `u_hr_01`  
Question: `Show the merger risk memo.`

What to show:

- Legal content appears as a candidate result but is blocked.
- The UI explains exactly why access was denied.
- The audit log records the blocked retrieval attempt.

Why recruiters care:

- Shows least-privilege enforcement during retrieval, not after generation.
- Makes policy decisions legible for debugging, compliance, and demos.

## 4. Malicious prompt-injection document

User: `u_it_01`  
Question: `Any security runbook updates?`

What to show:

- The malicious runbook is retrieved as relevant content.
- The system flags patterns like `ignore permissions` and `reveal secrets`.
- The document is blocked from assistant context even though the user could otherwise access internal docs.

Why recruiters care:

- Demonstrates an important RAG threat model with realistic malicious context.
- Shows security filtering of retrieved documents before anything is sent to a model.
