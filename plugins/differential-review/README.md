# Differential Security Review

Security-focused code change analysis with EdTech-specific threat modeling.

## What it does

Performs a structured security review of code changes (PRs, diffs) with:

- **Risk-based triage** — classifies changes by security impact, not just size
- **EdTech threat modeling** — student PII, role escalation, tenant isolation, assessment integrity
- **Blast radius estimation** — maps downstream impact of changes
- **Adversarial modeling** — thinks like an attacker targeting educational platforms
- **Structured reporting** — generates markdown reports with severity-rated findings

## When to use

- Before merging PRs that touch auth, data models, API endpoints, or student data
- During security-focused code reviews
- When auditing changes to LLM integrations or permission systems

## Usage

```
/differential-review
```

Or invoke manually: "Review the current PR for security issues using the differential review methodology."

## Files

| File | Purpose |
|---|---|
| `SKILL.md` | Main entry point — decision tree, quick reference, anti-patterns |
| `methodology.md` | 7-phase review workflow |
| `patterns.md` | Common vulnerability patterns with code examples |
| `reporting.md` | Report template and severity definitions |
