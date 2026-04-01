---
name: madlen:auth-flow-review
description: Review authentication and authorization implementation for security vulnerabilities
argument-hint: "[directory or file path] [--focus auth|session|rbac|tenant|oauth]"
allowed-tools: Read, Write, Grep, Glob, Bash
---

Parse `$ARGUMENTS` to determine:
1. **Scope**: Directory or files to audit (default: entire project)
2. **Focus**: Specific auth component to prioritize (default: all phases)

Load and follow the methodology in `skills/auth-flow-review/SKILL.md`. Execute all 5 audit phases and generate a report file named `auth-review-{date}.md`.
