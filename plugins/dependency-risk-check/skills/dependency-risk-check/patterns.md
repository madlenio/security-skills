# Common Dependency Risk Patterns

## Pattern 1: Known Vulnerability Ignored

```json
// package.json — using a version with known CVE
{
  "dependencies": {
    "lodash": "4.17.15"  // CVE-2020-8203: Prototype Pollution (fixed in 4.17.19)
  }
}

// FIX: Update to patched version
{
  "dependencies": {
    "lodash": "4.17.21"
  }
}
```

## Pattern 2: Abandoned Core Dependency

```json
// package.json — critical dependency with no updates in 3+ years
{
  "dependencies": {
    "some-auth-lib": "2.1.0"  // Last publish: 2021, GitHub archived, 200+ open issues
  }
}

// WARNING SIGNS:
// - npm info some-auth-lib time.modified → "2021-03-15T..."
// - GitHub repo shows "archived" banner
// - Multiple unpatched security issues in GitHub issues

// FIX: Migrate to maintained alternative
{
  "dependencies": {
    "maintained-auth-lib": "5.0.0"  // Active development, regular releases
  }
}
```

## Pattern 3: Typosquatting Risk

```json
// Legitimate vs. malicious look-alikes:
{
  "dependencies": {
    "lodash": "4.17.21",     // ✅ Legitimate
    "1odash": "1.0.0",       // ❌ Typosquat (l→1)
    "lodahs": "1.0.0",       // ❌ Typosquat (transposed letters)
    "lodassh": "1.0.0",      // ❌ Typosquat (double letter)

    "express": "4.18.0",     // ✅ Legitimate
    "expres": "1.0.0",       // ❌ Typosquat (missing letter)
    "expresss": "1.0.0",     // ❌ Typosquat (extra letter)
  }
}

// CHECK: Compare against npm's top 1000 packages
// Low weekly downloads + similar name to popular package = suspicious
```

## Pattern 4: Dangerous Install Scripts

```json
// package.json of a dependency — runs code during npm install
{
  "scripts": {
    "postinstall": "node setup.js"  // What does this do?
  }
}

// setup.js might:
// - Download additional code from the internet
// - Read environment variables (tokens, keys)
// - Modify system files
// - Exfiltrate data

// CHECK: Review postinstall scripts of all dependencies
// find node_modules -name "package.json" -maxdepth 2 -exec grep -l "postinstall" {} \;
```

## Pattern 5: License Conflict

```json
// package.json — commercial SaaS project using AGPL dependency
{
  "license": "UNLICENSED",  // Proprietary/commercial
  "dependencies": {
    "agpl-database-lib": "3.0.0"  // AGPL-3.0 → Requires open-sourcing your code
  }
}

// FIX: Replace with permissively licensed alternative
{
  "dependencies": {
    "mit-database-lib": "5.0.0"  // MIT → Safe for commercial use
  }
}
```

## Pattern 6: Unpinned Versions

```json
// RISKY: Caret ranges allow minor/patch updates
{
  "dependencies": {
    "critical-auth": "^2.0.0",  // Could install 2.9.9 with breaking changes
    "data-lib": "*"             // Could install ANY version
  }
}

// SAFER: Exact versions for critical dependencies
{
  "dependencies": {
    "critical-auth": "2.3.1",   // Exact version
    "data-lib": "~1.5.0"       // Only patch updates (1.5.x)
  }
}

// BEST: Use lockfile + exact pinning for security-critical deps
// AND have Dependabot/Renovate for automated, reviewed updates
```

## Pattern 7: Excessive Transitive Dependencies

```bash
# Check dependency tree depth
npm ls --all 2>/dev/null | wc -l
# If >1000 packages, the attack surface is very large

# Find deeply nested deps
npm ls --all 2>/dev/null | grep -E "^│\s+│\s+│\s+│" | head -20
# 4+ levels deep = you're trusting unknown maintainers
```

## Pattern 8: No Lockfile Committed

```bash
# CHECK: Is lockfile in version control?
git ls-files | grep -E "package-lock|yarn.lock|pnpm-lock"

# If empty → RISK: Different developers get different dependency versions
# This means untested dependency combinations and potential supply chain issues

# Also check .gitignore doesn't exclude it
grep -E "lock" .gitignore
```

## Pattern 9: Outdated Security-Critical Dependencies

```bash
# These packages should ALWAYS be on latest patch:
# - bcrypt / argon2 (password hashing)
# - jsonwebtoken / jose (token handling)
# - helmet (security headers)
# - express (web framework)
# - next (framework with SSR)
# - DOMPurify (XSS prevention)

npm outdated --json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
critical = ['bcrypt','argon2','jsonwebtoken','jose','helmet','express','next','dompurify','isomorphic-dompurify']
for pkg in critical:
    if pkg in data:
        print(f'⚠️  {pkg}: current={data[pkg][\"current\"]}, latest={data[pkg][\"latest\"]}')
" 2>/dev/null
```

## Pattern 10: EdTech-Specific Risky Dependencies

```json
// Dependencies that handle student data — extra scrutiny needed:
{
  "dependencies": {
    // Analytics: What data do they collect?
    "posthog-js": "1.x",        // Check: data collection scope, PII handling
    "mixpanel-browser": "2.x",  // Check: COPPA compliance, data retention

    // LLM: Do they log prompts?
    "openai": "4.x",            // Check: logging config, data retention policy
    "@anthropic-ai/sdk": "0.x", // Check: same

    // PDF generation: SSRF/RCE risks
    "puppeteer": "21.x",        // Check: sandbox enabled, no user-controlled URLs
    "wkhtmltopdf": "0.x",       // Check: known SSRF vulnerabilities

    // Rich text: XSS surface
    "@tiptap/core": "2.x",      // Check: output sanitization defaults
    "quill": "1.x",             // Check: HTML output handling
  }
}
```
