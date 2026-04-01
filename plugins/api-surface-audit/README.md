# API Surface Audit

Map and audit all exposed API endpoints for security gaps.

## What it does

Complete API surface analysis:

- **Endpoint discovery** — Enumerate all routes across frameworks
- **Auth coverage** — Identify unprotected endpoints
- **Authorization matrix** — Map role access per endpoint
- **Input validation** — Check for unvalidated user input
- **Rate limiting** — Verify abuse prevention
- **Response security** — Headers, CORS, error handling

## When to use

- After adding new API endpoints
- When preparing for penetration testing
- As part of regular security audits
- Before exposing APIs to third-party integrations

## Usage

```
/api-surface-audit
```

## Files

| File | Purpose |
|---|---|
| `SKILL.md` | 6-phase audit with endpoint discovery scripts |
| `patterns.md` | Common API security anti-patterns |
| `reporting.md` | API audit report template with auth matrix |
