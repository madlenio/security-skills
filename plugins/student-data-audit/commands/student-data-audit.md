---
name: madlen:student-data-audit
description: Audit codebase for student PII exposure, data protection gaps, and compliance issues
argument-hint: "[directory or file path] [--compliance ferpa,coppa,gdpr,kvkk]"
allowed-tools: Read, Write, Grep, Glob, Bash
---

Parse `$ARGUMENTS` to determine:
1. **Scope**: Directory or files to audit (default: entire project)
2. **Compliance**: Which regulations to check against (default: all — FERPA, COPPA, GDPR, KVKK)

Load and follow the methodology in `skills/student-data-audit/SKILL.md`. Execute all 5 audit phases and generate a markdown report file in the project root named `student-data-audit-{date}.md`.
