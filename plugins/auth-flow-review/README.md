# Auth Flow Review

Review authentication and authorization for security vulnerabilities.

## What it does

Comprehensive auth audit covering:

- **Authentication** — Password hashing, token generation, OAuth/SSO flows
- **Session management** — Token storage, expiry, rotation, revocation
- **Authorization** — RBAC enforcement, IDOR prevention, tenant isolation
- **EdTech-specific** — Student impersonation, parent-child linking, assessment lockdown

## When to use

- When building or modifying authentication flows
- After security incidents involving unauthorized access
- When adding new roles or changing the permission model
- Before SOC 2 or penetration testing engagements

## Usage

```
/auth-flow-review
```

## Files

| File | Purpose |
|---|---|
| `SKILL.md` | 5-phase audit with EdTech role hierarchy checks |
| `patterns.md` | Common auth vulnerability patterns |
| `reporting.md` | Auth review report template |
