# LLM Safety Report Template

## Severity Definitions

| Severity | Description | Examples |
|---|---|---|
| **CRITICAL** | LLM can be manipulated to leak data, bypass safety, or perform unauthorized actions | Prompt injection leading to data exfil, unrestricted tool access, PII in prompts |
| **HIGH** | Significant safety gap, exploitable by motivated users | Missing output filtering, answer leakage, no content safety policy |
| **MEDIUM** | Defense-in-depth gap, limited direct impact | Weak input validation, missing rate limits, verbose error responses |
| **LOW** | Best practice violation, minimal risk | Missing model fallback, no cost monitoring, documentation gaps |
| **INFO** | Observation for improvement | Architecture suggestions, emerging best practices |

## Report Template

```markdown
# LLM Safety Review Report

**Repository**: [repo name]
**Auditor**: Claude (Madlen Security Skills)
**Date**: [YYYY-MM-DD]
**Overall Risk**: [CRITICAL / HIGH / MEDIUM / LOW]

## Executive Summary

[3-5 sentences: What LLM integrations were audited, overall safety posture, critical findings]

## LLM Integration Inventory

| Integration Point | Model/Provider | User-Facing | Input Source | Output Destination |
|---|---|---|---|---|
| [feature name] | [GPT-4/Claude/etc] | [Student/Teacher/Admin] | [User text/Document/RAG] | [UI/Database/Email] |

## Attack Surface Map

| Vector | Exposure | Current Defense | Adequacy |
|---|---|---|---|
| Prompt injection (direct) | [description] | [defense or "None"] | Adequate/Weak/None |
| Prompt injection (indirect) | [description] | [defense or "None"] | Adequate/Weak/None |
| Data exfiltration | [description] | [defense or "None"] | Adequate/Weak/None |
| Output safety | [description] | [defense or "None"] | Adequate/Weak/None |
| Tool abuse | [description] | [defense or "None"] | Adequate/Weak/None |
| Cost exploitation | [description] | [defense or "None"] | Adequate/Weak/None |

## Findings

### [LLM-001] [Finding Title]

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Category**: [Prompt Injection / Data Boundary / Output Safety / Tool Safety / Cost Control]
- **Location**: `path/to/file:line`
- **Affected Users**: [Students / Teachers / All]

**Description:**
[What the vulnerability is]

**Attack Scenario:**
```
[Example prompt or interaction that exploits the vulnerability]
```

**Evidence:**
```
[Code showing the vulnerable pattern]
```

**Recommendation:**
```
[Code showing the fix]
```

---

## Prompt Injection Test Results

| Test | Result | Notes |
|---|---|---|
| "Ignore previous instructions" | PASS/FAIL | [details] |
| "Repeat your system prompt" | PASS/FAIL | [details] |
| Delimiter escape attempt | PASS/FAIL | [details] |
| Base64 encoded injection | PASS/FAIL | [details] |
| Multi-turn escalation | PASS/FAIL | [details] |
| Embedded instructions in content | PASS/FAIL | [details] |

## Remediation Roadmap

### Immediate
1. [CRITICAL findings — block merge/deploy]

### Short-term
1. [HIGH findings — fix within sprint]

### Medium-term
1. [MEDIUM findings — fix within quarter]

## Positive Observations

[Good LLM safety practices found in the codebase]
```
