# Student Data Audit Report Template

## Severity Definitions

| Severity | Description | EdTech Examples |
|---|---|---|
| **CRITICAL** | Active PII exposure or compliance violation with legal risk. Data is already leaking or trivially exploitable. | Student names/emails in PostHog events, unauth'd student data endpoint, PII in URL params |
| **HIGH** | Significant data protection gap, exploitable with moderate effort by a motivated actor. | `dangerouslySetInnerHTML` with unsanitized LLM output, analytics `track()` spreading all args to 3rd parties, JWT in localStorage without short expiry |
| **MEDIUM** | Defense-in-depth gap. Not directly exploitable alone, but weakens the overall security posture. | Error sanitizer redacting tokens but not emails, `console.error` with student IDs in production, generated API client caching full student objects |
| **LOW** | Best practice violation with minimal direct risk. | Missing CSP headers, debug console.log statements, no explicit retention policy in frontend |
| **INFO** | Observation — no direct risk, but worth noting for architecture decisions. Often indicates backend/legal action needed. | No KVKK consent UI (may exist server-side), no data export feature in frontend |

## Audit Scope

Specify the audit scope at the top of every report:

| Scope | What's Covered | What's NOT Covered |
|---|---|---|
| **Full-stack** | Frontend + backend + database + infrastructure | External vendor security |
| **Frontend-only** | Client-side code, API client usage, localStorage, analytics, rendered content | Backend access controls, DB encryption, server logs, infra |
| **Backend-only** | Server code, DB queries, API auth, logging, external integrations | Client-side rendering, XSS, localStorage |

## Report Template

```markdown
# Student Data Audit Report

**Repository**: [repo name]
**Auditor**: Claude (Madlen Security Skills)
**Date**: [YYYY-MM-DD]
**Overall Risk**: [CRITICAL / HIGH / MEDIUM / LOW]

## Executive Summary

[3-5 sentences: What was audited, overall posture, most critical finding, recommended priority action]

## Data Inventory

### Student Data Locations

| Location | Data Type | Sensitivity | Encrypted | Access Controlled |
|---|---|---|---|---|
| [database.table] | [Direct PII / Records / Behavioral] | [CRITICAL/HIGH/MEDIUM] | YES/NO | YES/NO |

### External Data Flows

| Destination | Data Sent | Purpose | DPA in Place | Anonymized |
|---|---|---|---|---|
| [service name] | [data types] | [purpose] | YES/NO/UNKNOWN | YES/NO |

## Findings

### [SDA-001] [Finding Title]

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Category**: [PII Exposure / Access Control / Compliance / Retention / External Transfer]
- **Location**: `path/to/file:line`
- **Regulation**: [FERPA / COPPA / GDPR / KVKK / General Best Practice]

**Description:**
[What the issue is]

**Evidence:**
```
[Code snippet showing the vulnerability]
```

**Risk:**
[Who is affected, what data is exposed, what could happen]

**Recommendation:**
[Specific fix with code example]

**Compliance Impact:**
[Which regulation this violates and the specific clause/article]

---

## Compliance Gap Analysis

| Requirement | FERPA | COPPA | GDPR | KVKK | Status |
|---|---|---|---|---|---|
| Consent management | [req] | [req] | [req] | [req] | PASS/FAIL/N/A |
| Data minimization | - | [req] | [req] | [req] | PASS/FAIL |
| Right to deletion | - | [req] | [req] | [req] | PASS/FAIL |
| Breach notification | [req] | [req] | [req] | [req] | PASS/FAIL |
| Data retention limits | - | [req] | [req] | [req] | PASS/FAIL |
| Cross-border transfers | - | - | [req] | [req] | PASS/FAIL/N/A |

## Remediation Roadmap

### Immediate (before next release)
1. [CRITICAL findings]

### Short-term (within 2 weeks)
1. [HIGH findings]

### Medium-term (within quarter)
1. [MEDIUM findings]

## Positive Observations

[Security practices done well — reinforce good patterns]
```
