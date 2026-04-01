---
name: madlen:edtech-compliance
description: Scan codebase for FERPA, COPPA, GDPR, and KVKK compliance gaps
argument-hint: "[directory] [--compliance ferpa,coppa,gdpr,kvkk]"
allowed-tools: Read, Write, Grep, Glob, Bash
---

Parse `$ARGUMENTS` to determine:
1. **Scope**: Directory to audit (default: entire project)
2. **Regulations**: Which regulations to check (default: all applicable)

Load and follow the methodology in `skills/edtech-compliance/SKILL.md`. Determine applicable regulations, run per-regulation checklists, and generate a report file named `compliance-report-{date}.md`.
