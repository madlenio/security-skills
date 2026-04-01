# Contributing to Madlen Security Skills

Thank you for helping make EdTech more secure! Here's how to contribute.

## Adding a New Skill

### 1. Structure

Create your skill following this layout:

```
plugins/<your-skill-name>/
├── skills/<your-skill-name>/
│   ├── SKILL.md          # Main prompt (required)
│   ├── methodology.md    # Detailed workflow (if applicable)
│   ├── patterns.md       # Detection patterns with code examples
│   └── reporting.md      # Output template
├── commands/             # Slash command definitions (optional)
└── README.md             # Human-readable overview (required)
```

### 2. SKILL.md Guidelines

Your SKILL.md should include:

- **Quick reference table** — at-a-glance risk categorization
- **Decision tree** — route the analysis based on what's found
- **Concrete checks** — specific things to look for (not vague advice)
- **Code examples** — vulnerable vs. fixed patterns
- **Red flags** — immediate escalation criteria
- **Output requirements** — what the report must contain

### 3. Quality Checklist

Before submitting:

- [ ] Skill is tested on at least one real codebase
- [ ] Code examples are realistic and runnable
- [ ] Patterns cover the most common cases (not just edge cases)
- [ ] Report template is actionable (not just "this is bad")
- [ ] README clearly explains when to use the skill
- [ ] No proprietary or confidential information included

### 4. EdTech Focus

We specifically value skills that address:

- Student data protection (PII, educational records)
- Compliance (FERPA, COPPA, GDPR, KVKK)
- Multi-tenant isolation in school/district platforms
- AI safety in educational contexts
- Assessment integrity
- Age-appropriate content and interactions

## Improving Existing Skills

Found a gap in an existing skill? Great contributions include:

- **New patterns** — add vulnerability patterns you've seen in the wild
- **Better examples** — more realistic code snippets
- **Missing checks** — audit steps that should be included
- **Framework support** — patterns for additional frameworks (Django, Rails, etc.)

## Reporting Issues

If a skill gives incorrect advice, misses a vulnerability, or produces false positives:

1. Open an issue with the skill name in the title
2. Include the context (language, framework, what was missed)
3. If possible, include a minimal reproduction

## Code of Conduct

Be respectful, constructive, and security-minded. We're all here to make educational technology safer for students and teachers.
