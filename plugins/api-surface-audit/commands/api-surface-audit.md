---
name: madlen:api-surface-audit
description: Map and audit all API endpoints for authentication, authorization, and input validation
argument-hint: "[directory] [--focus auth|validation|rate-limiting|cors|all]"
allowed-tools: Read, Write, Grep, Glob, Bash
---

Parse `$ARGUMENTS` to determine:
1. **Scope**: Directory to audit (default: entire project)
2. **Focus**: Specific audit phase to prioritize (default: all phases)

Load and follow the methodology in `skills/api-surface-audit/SKILL.md`. Enumerate all endpoints, assess security controls, and generate a report file named `api-audit-{date}.md`.
