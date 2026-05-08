# RULES

## Build rules

- keep the implementation lightweight and local-first
- no paid APIs required
- no hidden policy logic
- every blocked or flagged action should have a human-readable reason
- prioritize demo clarity over architecture depth

## Security rules

- never send blocked documents into assistant context
- never send injection-flagged documents into assistant context
- always mask detected PII before answer construction
- always record audit evidence for each query run
