# Dependency Risk Check

Audit dependencies for vulnerabilities, abandonment, supply chain risks, and license compliance.

## What it does

Goes beyond `npm audit`:

- **Vulnerability scanning** — Known CVEs with exploitability context
- **Abandonment detection** — Unmaintained packages, archived repos, inactive maintainers
- **Supply chain analysis** — Install scripts, typosquatting, native bindings
- **License compliance** — GPL/AGPL conflicts in commercial projects
- **EdTech-specific** — Analytics SDKs, LLM clients, PDF generators, rich text editors

## When to use

- As part of regular security audits
- Before major releases or compliance reviews
- When adding new dependencies to the project
- When Dependabot/Renovate flags updates

## Usage

```
/dependency-risk-check
```

## Files

| File | Purpose |
|---|---|
| `SKILL.md` | 6-phase audit with scanner commands for npm/pip |
| `patterns.md` | Common dependency risk patterns |
| `reporting.md` | Risk report template with remediation roadmap |
