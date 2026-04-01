# Dependency Risk Report Template

```markdown
# Dependency Risk Report

**Repository**: [repo name]
**Package Manager**: [npm / yarn / pnpm / pip]
**Auditor**: Claude (Madlen Security Skills)
**Date**: [YYYY-MM-DD]
**Overall Risk**: [CRITICAL / HIGH / MEDIUM / LOW]

## Executive Summary

[Total deps, vulnerability count by severity, abandoned packages found, license issues]

## Dependency Statistics

| Metric | Count |
|---|---|
| Direct dependencies | [n] |
| Dev dependencies | [n] |
| Total (incl. transitive) | [n] |
| With known vulnerabilities | [n] |
| Potentially abandoned | [n] |
| License issues | [n] |

## Vulnerability Scan Results

| Package | Version | Vulnerability | CVSS | Severity | Fix Available |
|---|---|---|---|---|---|
| [pkg] | [ver] | [CVE-XXXX-XXXX] | [score] | CRITICAL/HIGH/MEDIUM/LOW | [patched version or "No"] |

## Abandonment Risk Assessment

| Package | Last Updated | Downloads/Week | Open Issues | Status |
|---|---|---|---|---|
| [pkg] | [date] | [count] | [count] | Active/Slow/Abandoned |

## License Compliance

| Package | License | Compatible | Risk |
|---|---|---|---|
| [pkg] | [MIT/GPL/etc] | YES/NO | LOW/MEDIUM/HIGH |

## Supply Chain Risks

| Package | Install Scripts | Native Code | Single Maintainer | Risk |
|---|---|---|---|---|
| [pkg] | YES/NO | YES/NO | YES/NO | [level] |

## Findings

### [DEP-001] [Finding Title]

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Category**: [Vulnerability / Abandonment / License / Supply Chain / Version Pinning]
- **Package**: [package name @ version]

**Description:**
[What the risk is]

**Impact:**
[What could happen if exploited/unaddressed]

**Recommendation:**
[Update to version X / Replace with Y / Remove]

---

## Remediation Roadmap

### Immediate (security vulnerabilities)
1. [CRITICAL/HIGH CVE fixes]

### Short-term (within sprint)
1. [Abandoned package migrations]

### Medium-term (within quarter)
1. [License cleanup, version pinning improvements]

## Recommended Tooling

| Tool | Purpose | Status |
|---|---|---|
| Dependabot/Renovate | Automated dependency updates | CONFIGURED/MISSING |
| npm audit / snyk | Vulnerability scanning in CI | CONFIGURED/MISSING |
| license-checker | License compliance checking | CONFIGURED/MISSING |
| socket.dev | Supply chain risk detection | CONFIGURED/MISSING |
```
