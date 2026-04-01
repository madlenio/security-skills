# Compliance Report Template

```markdown
# EdTech Compliance Report

**Repository**: [repo name]
**Auditor**: Claude (Madlen Security Skills)
**Date**: [YYYY-MM-DD]
**Applicable Regulations**: [FERPA / COPPA / GDPR / KVKK]

## Executive Summary

[Overall compliance posture, most critical gaps, recommended priority actions]

## Regulation Applicability

| Regulation | Applies | Reason |
|---|---|---|
| FERPA | YES/NO | [US school data, student records, etc.] |
| COPPA | YES/NO | [Under-13 users possible, etc.] |
| GDPR | YES/NO | [EU users, EU data processing, etc.] |
| KVKK | YES/NO | [Turkish users, Turkish data, etc.] |

## Compliance Matrix

| Requirement | FERPA | COPPA | GDPR | KVKK |
|---|---|---|---|---|
| Privacy policy | PASS/FAIL | PASS/FAIL | PASS/FAIL | PASS/FAIL |
| Consent management | PASS/FAIL | PASS/FAIL | PASS/FAIL | PASS/FAIL |
| Data minimization | N/A | PASS/FAIL | PASS/FAIL | PASS/FAIL |
| Age verification | N/A | PASS/FAIL | N/A | N/A |
| Right to access | PASS/FAIL | N/A | PASS/FAIL | PASS/FAIL |
| Right to deletion | N/A | PASS/FAIL | PASS/FAIL | PASS/FAIL |
| Data portability | N/A | N/A | PASS/FAIL | N/A |
| Breach notification | PASS/FAIL | PASS/FAIL | PASS/FAIL | PASS/FAIL |
| Data retention limits | N/A | PASS/FAIL | PASS/FAIL | PASS/FAIL |
| Cross-border transfers | N/A | N/A | PASS/FAIL | PASS/FAIL |
| DPA with processors | N/A | N/A | PASS/FAIL | PASS/FAIL |
| Access logging | PASS/FAIL | N/A | N/A | PASS/FAIL |

## Findings

### [COMP-001] [Finding Title]

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Regulation**: [FERPA / COPPA / GDPR / KVKK]
- **Article/Clause**: [Specific legal reference]
- **Location**: `path/to/file:line`

**Gap Description:**
[What's missing or non-compliant]

**Legal Risk:**
[Potential penalties or legal exposure]

**Evidence:**
```
[Code showing the compliance gap]
```

**Recommendation:**
[Specific technical fix + any legal consultation needed]

---

## Remediation Roadmap

### Immediate (legal risk — before next release)
1. [CRITICAL gaps]

### Short-term (within 30 days)
1. [HIGH gaps]

### Medium-term (within quarter)
1. [MEDIUM gaps]

## Items Requiring Legal Review

| Item | Regulation | Why Legal Input Needed |
|---|---|---|
| [item] | [reg] | [reason — e.g., consent wording, DPA terms, etc.] |

## Disclaimer

This audit identifies technical compliance gaps in the codebase. It is not legal advice. Consult qualified legal counsel for regulatory compliance decisions, especially regarding consent wording, data processing agreements, and cross-border transfer mechanisms.
```
