# Frontend XSS Audit Report Template

```markdown
# Frontend XSS Audit Report

**Repository**: [repo name]
**Framework**: [React / Vue / Angular / Vanilla JS]
**Auditor**: Claude (Madlen Security Skills)
**Date**: [YYYY-MM-DD]
**Overall Risk**: [CRITICAL / HIGH / MEDIUM / LOW]

## Executive Summary

[XSS vector count, most critical finding, sanitization coverage, CSP status]

## XSS Vector Inventory

| # | Location | Type | Source | Sanitized | Severity |
|---|---|---|---|---|---|
| 1 | `src/components/Comment.tsx:42` | dangerouslySetInnerHTML | User comment | NO | CRITICAL |
| 2 | `src/features/ai/Response.tsx:18` | dangerouslySetInnerHTML | LLM output | DOMPurify | LOW |
| 3 | `src/components/Link.tsx:12` | href attribute | User URL | NO protocol check | HIGH |

## Sanitization Coverage

| Content Type | Instances | Sanitized | Coverage |
|---|---|---|---|
| User HTML rendering | [n] | [n] | [%] |
| LLM output rendering | [n] | [n] | [%] |
| Markdown rendering | [n] | [n] | [%] |
| URL handling | [n] | [n] | [%] |
| postMessage handlers | [n] | [n] | [%] |

## Content Security Policy

| Directive | Value | Status |
|---|---|---|
| default-src | [value] | OK/MISSING |
| script-src | [value] | OK/WEAK/MISSING |
| style-src | [value] | OK/WEAK/MISSING |
| img-src | [value] | OK/MISSING |
| frame-ancestors | [value] | OK/MISSING |

## Findings

### [XSS-001] [Finding Title]

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Type**: [DOM XSS / Reflected / Stored / LLM-injected]
- **Location**: `path/to/file:line`
- **Affected Users**: [Students / Teachers / All]

**Description:**
[What the vulnerability is]

**Proof of Concept:**
```
[XSS payload that triggers the vulnerability]
```

**Impact:**
[What an attacker can do — cookie theft, session hijacking, data exfiltration]

**Recommendation:**
```tsx
[Fixed code]
```

---

## Remediation Summary

| # | Severity | Finding | Fix Effort |
|---|---|---|---|
| XSS-001 | CRITICAL | [title] | [hours] |
```
