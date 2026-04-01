# API Surface Audit Report Template

```markdown
# API Surface Audit Report

**Repository**: [repo name]
**Auditor**: Claude (Madlen Security Skills)
**Date**: [YYYY-MM-DD]
**Overall Risk**: [CRITICAL / HIGH / MEDIUM / LOW]

## Executive Summary

[Total endpoints found, auth coverage %, critical gaps identified]

## Endpoint Inventory

### Unauthenticated Endpoints

| Method | Path | Purpose | Intentional | Risk |
|---|---|---|---|---|
| [GET/POST] | [path] | [purpose] | YES/NO | [CRITICAL/OK] |

### Authenticated Endpoints

| Method | Path | Auth | Roles | Rate Limited | Validated | Risk |
|---|---|---|---|---|---|---|
| [method] | [path] | YES | [roles] | YES/NO | YES/NO | [level] |

## Coverage Summary

| Category | Count | Percentage |
|---|---|---|
| Total endpoints | [n] | 100% |
| Authenticated | [n] | [%] |
| Role-authorized | [n] | [%] |
| Input validated | [n] | [%] |
| Rate limited | [n] | [%] |

## Authorization Matrix

| Endpoint | Student | Teacher | Parent | Admin |
|---|---|---|---|---|
| GET /api/students | - | READ | READ (own child) | READ |
| PUT /api/grades | - | WRITE (own class) | - | WRITE |

## Findings

### [API-001] [Finding Title]

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Category**: [Auth / Authz / Validation / Rate Limiting / Disclosure / CORS]
- **Endpoint**: `[METHOD] [path]`
- **Location**: `path/to/file:line`

**Description:**
[What the issue is]

**Evidence:**
```
[Code snippet]
```

**Recommendation:**
```
[Fixed code]
```

---

## Security Headers Check

| Header | Present | Value | Status |
|---|---|---|---|
| Strict-Transport-Security | YES/NO | [value] | OK/MISSING |
| X-Content-Type-Options | YES/NO | [value] | OK/MISSING |
| X-Frame-Options | YES/NO | [value] | OK/MISSING |
| Content-Security-Policy | YES/NO | [value] | OK/MISSING/WEAK |
| CORS | YES/NO | [origins] | OK/TOO_PERMISSIVE |

## Remediation Summary

| # | Severity | Finding | Endpoint | Fix Effort |
|---|---|---|---|---|
| API-001 | CRITICAL | [title] | [endpoint] | [hours] |
```
