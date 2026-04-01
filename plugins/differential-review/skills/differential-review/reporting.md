# Reporting Template

## Severity Definitions

| Severity | Description | Examples | SLA |
|---|---|---|---|
| **CRITICAL** | Actively exploitable, data breach or full compromise likely | Auth bypass, SQL injection, PII exposure, RCE | Fix before merge |
| **HIGH** | Exploitable with some effort, significant impact | XSS, IDOR, missing rate limits, broken access control | Fix before merge |
| **MEDIUM** | Limited exploitability or impact, defense-in-depth gap | Missing CSRF token, verbose errors, weak session config | Fix within sprint |
| **LOW** | Minimal risk, best practice violation | Missing security headers, outdated deps (no known exploit) | Track in backlog |
| **INFO** | Observation, no direct risk | Code quality, potential future concern, documentation gap | Optional |

## Report Template

```markdown
# Security Review Report

**PR**: #[number] — [title]
**Author**: [name]
**Reviewer**: Claude (Madlen Security Skills)
**Date**: [YYYY-MM-DD]
**Risk Level**: [CRITICAL / HIGH / MEDIUM / LOW]

## Summary

[2-3 sentence overview of what changed and the overall security posture]

## Change Inventory

| File | Risk Tier | Category |
|---|---|---|
| [file path] | CRITICAL/HIGH/MEDIUM/LOW | Auth/Data/API/UI/Config |

## Findings

### [F-001] [Finding Title]

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Location**: `path/to/file.ts:42`
- **Category**: [Auth / Data Exposure / Injection / Access Control / Configuration]

**Description:**
[What the vulnerability is and why it matters]

**Attack Scenario:**
[Step-by-step how an attacker would exploit this]

**Evidence:**
```
[Relevant code snippet or diff]
```

**Blast Radius:**
[What downstream systems/users are affected]

**Recommendation:**
[Specific fix with code example if possible]

---

### [F-002] [Next Finding]
[Same structure as above]

## Test Coverage Assessment

| Security Control | Has Test | Notes |
|---|---|---|
| [control name] | YES/NO | [details] |

## Blast Radius Summary

[Overall impact assessment — who is affected if this ships with the identified issues]

## Recommendations Summary

| # | Severity | Finding | Status |
|---|---|---|---|
| F-001 | CRITICAL | [title] | Must fix |
| F-002 | HIGH | [title] | Must fix |
| F-003 | MEDIUM | [title] | Should fix |

## Positive Observations

[Things done well — reinforce good security practices]
```

## Writing Guidelines

1. **Be specific**: File paths, line numbers, exact code snippets
2. **Be actionable**: Every finding must have a concrete recommendation
3. **Be honest about severity**: Don't inflate to seem thorough, don't minimize to be polite
4. **Show attack scenarios**: "An attacker could..." is more compelling than "This is insecure"
5. **Acknowledge good work**: Note security practices done well
6. **One finding per issue**: Don't bundle multiple problems into one finding
