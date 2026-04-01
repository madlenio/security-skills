# Student Data Audit Report Template

## Severity Definitions

| Severity | Description | Examples |
|---|---|---|
| **CRITICAL** | Active PII exposure, compliance violation with legal risk | Unencrypted PII in logs, student data in analytics, no auth on student endpoints |
| **HIGH** | Significant data protection gap, exploitable with moderate effort | Over-fetched API responses, missing tenant isolation, PII in error messages |
| **MEDIUM** | Defense-in-depth gap, limited direct exposure | Missing retention policies, weak anonymization, client-side PII caching |
| **LOW** | Best practice violation, no direct exposure | Missing privacy headers, verbose error codes, documentation gaps |
| **INFO** | Observation for future improvement | Architecture suggestions, tooling recommendations |

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
