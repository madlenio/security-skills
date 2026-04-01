# Student Data Audit

Scan codebases for student PII exposure, insecure data storage, and compliance gaps.

## What it does

Performs a comprehensive audit of how student data is handled:

- **Data inventory** — maps every location where student data is stored, processed, or transmitted
- **Storage security** — checks encryption, access controls, audit logging
- **Data flow analysis** — traces PII through frontend, backend, logs, analytics, caches, and LLMs
- **Compliance check** — FERPA, COPPA, GDPR, KVKK gap analysis
- **Lifecycle audit** — collection consent, retention policies, deletion capabilities

## When to use

- When building or auditing EdTech applications that handle student records
- Before launching in new markets (GDPR for EU, KVKK for Turkey, etc.)
- After adding new data collection or external service integrations
- As part of regular security audits

## Usage

```
/student-data-audit
```

Or invoke manually: "Audit this codebase for student data protection issues."

## Files

| File | Purpose |
|---|---|
| `SKILL.md` | Main entry point — audit phases, decision tree, red flags |
| `patterns.md` | Common student data exposure patterns with code examples |
| `reporting.md` | Report template with compliance gap analysis |
