---
name: madlen:frontend-xss-audit
description: Detect XSS vulnerabilities in React, Vue, Angular, and vanilla JS frontends
argument-hint: "[directory] [--framework react|vue|angular|all]"
allowed-tools: Read, Write, Grep, Glob, Bash
---

Parse `$ARGUMENTS` to determine:
1. **Scope**: Directory to audit (default: entire project)
2. **Framework**: Which framework patterns to prioritize (default: auto-detect)

Load and follow the methodology in `skills/frontend-xss-audit/SKILL.md`. Execute all 6 audit phases and generate a report file named `xss-audit-{date}.md`.
