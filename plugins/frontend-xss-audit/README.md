# Frontend XSS Audit

Detect Cross-Site Scripting vulnerabilities in React, Vue, Angular, and vanilla JS.

## What it does

- **Unsafe HTML rendering** — dangerouslySetInnerHTML, v-html, innerHTML
- **URL-based XSS** — javascript: protocol, open redirects
- **Code execution** — eval, postMessage without origin checks
- **LLM output XSS** — AI-generated content rendered as HTML (EdTech-specific)
- **CSP assessment** — Content Security Policy configuration

## When to use

- After adding user-generated content features (comments, submissions, chat)
- When integrating LLM output into the UI
- After modifying markdown rendering configuration
- Before penetration testing engagements

## Usage

```
/frontend-xss-audit
```

## Files

| File | Purpose |
|---|---|
| `SKILL.md` | 6-phase audit with per-framework search commands |
| `patterns.md` | XSS patterns per framework with PoC payloads |
| `reporting.md` | XSS audit report template |
