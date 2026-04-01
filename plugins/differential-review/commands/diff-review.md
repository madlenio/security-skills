---
name: madlen:diff-review
description: Security-focused differential code review with EdTech threat modeling
argument-hint: "[PR URL, branch name, or commit range] [--deep for full adversarial analysis]"
allowed-tools: Read, Write, Grep, Glob, Bash
---

Parse `$ARGUMENTS` to determine:
1. **Target**: The code to review (PR URL, branch, commit range, or current diff)
2. **Flags**: `--deep` for full adversarial modeling, default is standard review

If no arguments provided, review the current branch's diff against `main`.

Load and follow the methodology in `skills/differential-review/SKILL.md`. Execute all phases and generate a markdown report file in the project root named `security-review-{date}.md`.
