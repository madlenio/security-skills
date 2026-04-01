# Auth Flow Review Report Template

```markdown
# Auth Flow Review Report

**Repository**: [repo name]
**Auditor**: Claude (Madlen Security Skills)
**Date**: [YYYY-MM-DD]
**Overall Risk**: [CRITICAL / HIGH / MEDIUM / LOW]

## Authentication Architecture

[Text-based diagram of the auth flow]

```
Client → Login Request → Auth Server → Validate Credentials
                                      → Generate Tokens
                                      → Set Cookies/Headers
Client → API Request + Token → Auth Middleware → Validate Token
                                               → Extract User + Role
                                               → Route Handler → Authz Check → Data Access
```

## Auth Stack Summary

| Component | Implementation | Status |
|---|---|---|
| Password hashing | [bcrypt/argon2/etc] | SECURE/WEAK |
| Token type | [JWT/session/etc] | [details] |
| Token storage | [cookie/localStorage/etc] | SECURE/VULNERABLE |
| Session duration | [access: Xm, refresh: Xd] | APPROPRIATE/TOO_LONG |
| Rate limiting | [library/config] | PRESENT/MISSING |
| MFA | [method or N/A] | PRESENT/MISSING |
| OAuth/SSO | [provider or N/A] | SECURE/ISSUES |

## Role Hierarchy

| Role | Can Access | Verified |
|---|---|---|
| Student | Own data, assigned content | YES/NO |
| Teacher | Class data, student grades | YES/NO |
| Parent | Linked child data | YES/NO |
| School Admin | School-wide data | YES/NO |
| Platform Admin | All data | YES/NO |

## Endpoint Auth Coverage

| Endpoint | Auth | Authz | Rate Limited | Risk |
|---|---|---|---|---|
| POST /api/login | N/A | N/A | YES/NO | [risk] |
| GET /api/students | YES/NO | YES/NO | YES/NO | [risk] |

## Findings

### [AUTH-001] [Finding Title]

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Category**: [Authentication / Authorization / Session / Token / Rate Limiting]
- **Location**: `path/to/file:line`

**Description:**
[What the vulnerability is]

**Attack Scenario:**
[How an attacker would exploit this]

**Evidence:**
```
[Code snippet]
```

**Recommendation:**
```
[Fixed code]
```

---

## Remediation Summary

| # | Severity | Finding | Fix Effort |
|---|---|---|---|
| AUTH-001 | CRITICAL | [title] | [hours/days] |
```
