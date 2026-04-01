---
name: madlen:dependency-risk-check
description: Audit dependencies for vulnerabilities, abandonment, supply chain risks, and license compliance
argument-hint: "[--focus vulns|abandoned|license|supply-chain|all]"
allowed-tools: Read, Write, Grep, Glob, Bash
---

Parse `$ARGUMENTS` to determine:
1. **Focus**: Specific audit phase to prioritize (default: all phases)

Auto-detect package manager from lockfile. Load and follow the methodology in `skills/dependency-risk-check/SKILL.md`. Execute all 6 audit phases and generate a report file named `dependency-risk-{date}.md`.
