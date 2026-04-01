---
name: madlen:llm-safety-review
description: Audit LLM integrations for prompt injection, data exfiltration, and output safety
argument-hint: "[directory or file path] [--focus injection|data|output|tools|cost]"
allowed-tools: Read, Write, Grep, Glob, Bash
---

Parse `$ARGUMENTS` to determine:
1. **Scope**: Directory or files to audit (default: entire project)
2. **Focus**: Specific audit phase to prioritize (default: all phases)

Load and follow the methodology in `skills/llm-safety-review/SKILL.md`. Execute all audit phases and generate a markdown report file in the project root named `llm-safety-review-{date}.md`.
