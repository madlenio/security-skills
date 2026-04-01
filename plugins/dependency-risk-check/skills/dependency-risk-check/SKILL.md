# Dependency Risk Check

Audit project dependencies for known vulnerabilities, abandonment signals, supply chain risks, and license compliance. Goes beyond `npm audit` by analyzing maintainer health, typosquatting risk, and transitive dependency depth.

## Quick Reference

| Risk Category | Severity | What to Check |
|---|---|---|
| **Known CVEs** | CRITICAL-LOW | Published vulnerabilities with severity ratings |
| **Abandoned packages** | HIGH | No updates >2 years, archived repo, unresponsive maintainer |
| **Typosquatting** | CRITICAL | Package names similar to popular packages |
| **Excessive permissions** | HIGH | Install scripts, native bindings, network access |
| **Deep transitive deps** | MEDIUM | Dependencies of dependencies you don't control |
| **License conflicts** | MEDIUM | GPL in commercial projects, AGPL in SaaS |
| **Single maintainer** | MEDIUM | Bus factor of 1 on critical packages |
| **Unpinned versions** | LOW | `^` or `*` ranges allowing unexpected updates |

## Decision Tree

```
START → Identify package manager and lockfile
  │
  ├─ npm/yarn/pnpm (package.json + lockfile)
  │   └─ Run vulnerability scan → Analyze results
  │
  ├─ pip (requirements.txt / pyproject.toml)
  │   └─ Run safety/pip-audit → Analyze results
  │
  ├─ For each dependency:
  │   ├─ Has known CVEs?
  │   │   └─ YES → Rate by CVSS score, check if exploitable in this context
  │   │
  │   ├─ Is it abandoned?
  │   │   └─ Check last publish date, open issues/PRs, GitHub activity
  │   │
  │   ├─ Is it a typosquat risk?
  │   │   └─ Check name similarity to popular packages
  │   │
  │   ├─ Does it run install scripts?
  │   │   └─ YES → Review what the scripts do
  │   │
  │   └─ License compatible?
  │       └─ Check against project's license requirements
  │
  └─ Generate risk report with remediation steps
```

## Audit Phases

### Phase 1: Vulnerability Scan

Run built-in vulnerability scanners:

```bash
# npm
npm audit --json 2>/dev/null || echo "npm audit not available"

# yarn
yarn audit --json 2>/dev/null || echo "yarn audit not available"

# pnpm
pnpm audit --json 2>/dev/null || echo "pnpm audit not available"

# pip (Python)
pip-audit --format=json 2>/dev/null || safety check --json 2>/dev/null || echo "pip audit not available"
```

**For each vulnerability found:**

- [ ] What is the CVSS score and severity?
- [ ] Is the vulnerable code path actually used in this project?
- [ ] Is there a patched version available?
- [ ] If no patch, is there a workaround?
- [ ] For transitive deps: can the parent dep be updated to pull in the fix?

### Phase 2: Abandonment Analysis

```bash
# List all direct dependencies with versions
cat package.json | grep -E "\"dependencies\"|\"devDependencies\"" -A 1000 | grep -E "\"[^\"]+\":\s*\"" | head -100

# Check for lockfile
ls -la package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null

# Find packages not updated in >2 years (npm)
npm outdated --json 2>/dev/null | head -200
```

**Abandonment signals to check on npm/PyPI:**

| Signal | Risk | How to Check |
|---|---|---|
| Last publish >2 years ago | HIGH | `npm info <pkg> time.modified` |
| GitHub repo archived | HIGH | Repo page shows "archived" banner |
| Open issues >100 with no response | MEDIUM | GitHub issues tab |
| Open security PRs unmerged | HIGH | Pull requests with "security" label |
| Maintainer account inactive | MEDIUM | No GitHub activity in 12+ months |
| Deprecation notice | HIGH | `npm info <pkg> deprecated` |
| Downloads trending to zero | MEDIUM | npm trends |

### Phase 3: Supply Chain Risk

```bash
# Check for install scripts (npm)
find node_modules -name "package.json" -maxdepth 2 -exec grep -l "preinstall\|postinstall\|preuninstall" {} \; 2>/dev/null | head -20

# Check for native/compiled dependencies
find node_modules -name "binding.gyp" -o -name "*.node" 2>/dev/null | head -20

# Count total transitive dependencies
ls node_modules | wc -l 2>/dev/null

# Find dependencies with very few weekly downloads (potential typosquats)
# Manual check: compare package names against popular packages
```

**Supply chain checks:**

- [ ] **Install scripts**: Which packages run scripts during install? What do they do?
- [ ] **Native bindings**: Which packages compile native code? Are they from trusted sources?
- [ ] **Dependency depth**: How deep is the transitive dependency tree?
- [ ] **Typosquatting**: Are any package names suspiciously similar to popular packages?
- [ ] **Source verification**: Does the published package match the GitHub repo?

### Phase 4: License Compliance

```bash
# List all dependency licenses (npm)
npx license-checker --json --production 2>/dev/null | head -200

# Find problematic licenses
npx license-checker --production --failOn "GPL-2.0;GPL-3.0;AGPL-1.0;AGPL-3.0" 2>/dev/null
```

**License risk levels:**

| License | Risk for Commercial | Risk for SaaS | Notes |
|---|---|---|---|
| MIT, BSD, Apache 2.0 | LOW | LOW | Permissive, safe for commercial use |
| ISC | LOW | LOW | Permissive, similar to MIT |
| GPL-2.0 | HIGH | MEDIUM | Copyleft, may require source disclosure |
| GPL-3.0 | HIGH | HIGH | Strong copyleft |
| AGPL-3.0 | CRITICAL | CRITICAL | Network copyleft — SaaS must share source |
| LGPL | MEDIUM | LOW | Copyleft for library modifications only |
| Unlicensed / UNLICENSED | HIGH | HIGH | No license = all rights reserved |
| Custom | MEDIUM | MEDIUM | Needs legal review |

### Phase 5: Version Pinning & Update Strategy

```bash
# Check for unpinned versions in package.json
grep -E "\"\^|\"\~|\"\*|\">=|\">" package.json | head -30

# Check lockfile freshness
stat -f "%Sm" package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null

# Check for .nvmrc or engine constraints
cat .nvmrc 2>/dev/null; grep -A2 "engines" package.json 2>/dev/null
```

**Check for:**

- [ ] **Lockfile committed**: Is the lockfile in version control?
- [ ] **Version ranges**: Are critical deps pinned to exact versions?
- [ ] **Update cadence**: When was the last dependency update?
- [ ] **Automated updates**: Is Dependabot/Renovate configured?
- [ ] **Node/Python version**: Is the runtime version pinned?

### Phase 6: EdTech-Specific Dependency Concerns

| Concern | Why It Matters | What to Check |
|---|---|---|
| **Analytics SDKs** | May collect student data | PostHog, Mixpanel, GA — check data collection scope |
| **LLM client libraries** | May log prompts/completions | OpenAI, Anthropic SDKs — check logging config |
| **Auth libraries** | Critical security surface | passport, next-auth, clerk — check for known issues |
| **PDF/Doc generators** | May have SSRF or RCE risks | puppeteer, wkhtmltopdf — check sandbox settings |
| **Rich text editors** | XSS via content rendering | TinyMCE, Quill, Tiptap — check sanitization defaults |
| **File upload libraries** | Path traversal, size limits | multer, formidable — check config |

## Red Flags — Immediate Escalation

- Known CRITICAL/HIGH CVE with no patch available
- Dependency with active malware advisory
- Package with `postinstall` script that makes network requests
- AGPL-licensed dependency in commercial SaaS product
- Package name is 1-2 characters different from a popular package
- Dependency with no license file
- Core security package (auth, crypto) from single maintainer with no activity
- `node_modules` or `vendor` directory committed to git
- Lockfile not committed to version control
- Wildcard (`*`) version ranges on any dependency

## Output

Generate a structured report with:

1. Vulnerability scan results with severity ratings
2. Abandonment risk assessment for critical dependencies
3. Supply chain risk evaluation
4. License compliance matrix
5. Remediation steps prioritized by risk and effort

## Supporting Documents

- [patterns.md](patterns.md) — Common dependency risk patterns
- [reporting.md](reporting.md) — Report template
