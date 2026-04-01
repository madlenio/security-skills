# LLM Safety Review

Audit LLM integrations for prompt injection, data exfiltration, and output safety.

## What it does

Reviews AI/LLM integrations with education-specific concerns:

- **Prompt injection defense** — direct and indirect injection vectors
- **Data boundary audit** — PII in prompts, context windows, conversation history
- **Output safety** — content filtering, hallucination guards, age-appropriateness
- **Tool/function safety** — principle of least privilege, confirmation gates
- **Cost controls** — rate limits, token budgets, abuse prevention

## When to use

- When building or reviewing AI-powered educational features
- Before shipping LLM features to students (especially minors)
- After changing prompt templates, adding tools, or updating LLM providers
- As part of responsible AI assessments

## Usage

```
/llm-safety-review
```

Or invoke manually: "Review the LLM integrations in this codebase for safety issues."

## Files

| File | Purpose |
|---|---|
| `SKILL.md` | Main entry point — audit phases, decision tree, EdTech concerns |
| `patterns.md` | Common LLM vulnerability patterns with code examples |
| `reporting.md` | Report template with attack surface mapping |
