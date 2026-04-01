# EdTech Compliance Scanner

Automated compliance checklist scanning for FERPA, COPPA, GDPR, and KVKK.

## What it does

Scans your codebase against regulatory requirements for educational data:

- **FERPA** (US) — Student education records, consent, disclosure
- **COPPA** (US) — Children under 13, parental consent, data minimization
- **GDPR** (EU) — Data subject rights, lawful basis, DPIAs, breach notification
- **KVKK** (Turkey) — Explicit consent, VERBIS registration, data localization

## When to use

- Before launching in new markets (EU, Turkey, US schools)
- After adding new data collection or third-party integrations
- As part of regular compliance audits
- When preparing for SOC 2, ISO 27001, or vendor security reviews

## Usage

```
/edtech-compliance
/edtech-compliance --compliance gdpr,kvkk
```

## Files

| File | Purpose |
|---|---|
| `SKILL.md` | Per-regulation checklists with code-level checks |
| `patterns.md` | Common compliance anti-patterns |
| `reporting.md` | Compliance report template with gap matrix |
