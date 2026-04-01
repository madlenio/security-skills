# Madlen Security Skills

**Open-source Claude Code skills to help EdTech companies ship faster & more securely.**

Built by [Madlen.io](https://madlen.io) — from production experience building AI-powered educational tools, not theory.

## Why this exists

EdTech companies handle some of the most sensitive data on the planet: student records, learning analytics, assessment results. Yet most security tooling is built for fintech or enterprise SaaS. These skills bring security-first thinking to education technology — covering compliance (FERPA, COPPA, GDPR, KVKK), student data protection, LLM safety, and secure shipping practices.

## Skills

| Skill | Category | Purpose |
|---|---|---|
| [differential-review](plugins/differential-review/) | Code Auditing | Security-focused PR review with EdTech-specific threat modeling |
| [student-data-audit](plugins/student-data-audit/) | Data Protection | Scan for PII leaks, insecure storage of student data |
| [llm-safety-review](plugins/llm-safety-review/) | AI Safety | Audit LLM integrations for prompt injection, data exfiltration, output safety |

### Planned

| Skill | Category | Purpose |
|---|---|---|
| `edtech-compliance` | Compliance | FERPA, COPPA, GDPR, KVKK compliance checklist scanner |
| `auth-flow-review` | Authentication | Token handling, session management, RBAC review |
| `api-surface-audit` | API Security | Map exposed endpoints, check auth & rate-limiting |
| `frontend-xss-audit` | Frontend Security | React/Vue XSS vector detection |
| `dependency-risk-check` | Supply Chain | Audit deps for vulns + abandonment signals |

## Installation

### Claude Code (recommended)

```bash
claude /install-skill https://github.com/madlenio/security-skills
```

### Manual

Clone this repo and point Claude Code to the skill you want:

```bash
git clone https://github.com/madlenio/security-skills.git
# Then reference skills from your .claude/settings.json
```

## Skill Structure

Each skill follows a modular documentation architecture for token efficiency:

```
plugins/<skill-name>/
├── skills/<skill-name>/
│   ├── SKILL.md          # Main prompt — entry point, decision tree, quick reference
│   ├── methodology.md    # Detailed workflow phases
│   ├── patterns.md       # Detection patterns and common findings
│   └── reporting.md      # Output format and templates
├── commands/             # Slash command definitions
└── README.md             # Human-readable overview
```

## Contributing

We welcome contributions! Whether you're an EdTech developer, security researcher, or educator:

1. Fork the repo
2. Create a skill following the structure above
3. Test it on a real codebase
4. Open a PR with before/after examples

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## License

Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)

You're free to use, adapt, and share these skills — even commercially — as long as you give credit and share alike.

## About Madlen

[Madlen.io](https://madlen.io) is an AI-powered educational platform used by thousands of teachers. We build tools that make teaching smarter, not harder. This skills repository is our way of giving back to the EdTech community — helping everyone ship more securely.

---

**Built with care by the Madlen team. Star the repo if you find it useful.**
