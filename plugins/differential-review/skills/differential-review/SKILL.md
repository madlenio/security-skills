# Differential Security Review

Security-focused code change analysis with EdTech-specific threat modeling, blast radius estimation, and evidence-based findings.

## Quick Reference

| Change Risk | Indicators | Analysis Depth |
|---|---|---|
| **CRITICAL** | Auth/session changes, PII handling, role/permission logic, payment flows | Full adversarial modeling + blast radius |
| **HIGH** | API endpoints, data validation, file upload, database queries, LLM prompts | Dependency tracing + pattern matching |
| **MEDIUM** | UI state, routing, feature flags, config changes | Focused review + test coverage check |
| **LOW** | Styling, docs, comments, refactors (verify no behavior change) | Quick scan + regression check |

> **Remember**: Heartbleed was 2 lines. Risk is about *what* changed, not *how much*.

## Decision Tree

```
START → Gather context (git diff, PR description, related issues)
  │
  ├─ Are auth/session/token files changed?
  │   └─ YES → CRITICAL path: full methodology.md workflow
  │
  ├─ Does the change touch student data / PII fields?
  │   └─ YES → CRITICAL path + student-data-patterns.md
  │
  ├─ Are API endpoints added/modified?
  │   └─ YES → HIGH path: check auth middleware, rate limits, input validation
  │
  ├─ Does it modify LLM prompts or AI integration?
  │   └─ YES → HIGH path + cross-reference llm-safety patterns
  │
  ├─ Is it a dependency update?
  │   └─ YES → Check changelog for breaking/security changes, audit new transitive deps
  │
  └─ DEFAULT → Standard review with test coverage verification
```

## EdTech Threat Model

When reviewing code for educational platforms, always consider:

| Threat | Description | Common Vectors |
|---|---|---|
| **Student PII exposure** | Names, emails, grades, learning data leaking | Logs, error messages, API responses, analytics events |
| **Role escalation** | Student → Teacher → Admin privilege jumps | Missing middleware, client-side role checks, IDOR |
| **Cross-tenant data access** | Org A seeing Org B's data | Missing org_id filters, shared cache keys, broadcast events |
| **Assessment integrity** | Students accessing answers/rubrics | Predictable IDs, client-side answer storage, timing attacks |
| **Minor data (COPPA)** | Under-13 data requires parental consent | Age gates, consent flows, data retention policies |

## Workflow

Follow the phased approach in [methodology.md](methodology.md):

1. **Pre-Analysis** — Gather git context, PR metadata, changed file inventory
2. **Triage** — Classify risk level per file using the table above
3. **Code Analysis** — Line-by-line review of HIGH/CRITICAL files
4. **Test Coverage** — Verify security-relevant changes have test coverage
5. **Blast Radius** — Map downstream consumers of changed code
6. **Adversarial Modeling** — Think like an attacker targeting this change
7. **Report** — Generate structured findings per [reporting.md](reporting.md)

## Anti-Patterns to Flag

Immediately escalate if you see:

- [ ] Removed or weakened authentication checks
- [ ] Disabled CSRF/CORS protections
- [ ] `dangerouslySetInnerHTML` or `v-html` with user input
- [ ] Raw SQL queries with string interpolation
- [ ] Hardcoded secrets, API keys, or tokens
- [ ] `// TODO: add auth later` or similar deferred security
- [ ] Student data logged at INFO/DEBUG level
- [ ] Missing `org_id` filter in multi-tenant queries
- [ ] Client-side only permission checks without server validation
- [ ] LLM prompts that include raw user input without sanitization

## Output Requirements

Every review MUST produce a markdown report file (never chat-only findings). See [reporting.md](reporting.md) for the template.

## Supporting Documents

- [methodology.md](methodology.md) — Detailed 7-phase workflow
- [patterns.md](patterns.md) — Common vulnerability patterns with code examples
- [reporting.md](reporting.md) — Report template and severity definitions
