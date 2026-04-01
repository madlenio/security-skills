# Differential Review Methodology

## Pre-Analysis Setup

Before starting any review, gather full context:

```bash
# Get the diff
git diff main...HEAD --stat
git diff main...HEAD

# Get commit history for this branch
git log main...HEAD --oneline

# Identify changed files by category
git diff main...HEAD --name-only | sort

# Check for sensitive file patterns
git diff main...HEAD --name-only | grep -E "(auth|session|token|password|secret|config|env|migration|permission|role|student|grade|pii)"
```

**Context to gather:**
- PR description and linked issues
- Author's stated intent
- Files changed count and categories
- Whether this is a feature, bugfix, refactor, or dependency update

## Phase 1: Triage

Classify each changed file into a risk tier:

**CRITICAL files** (always deep-review):
- Authentication / authorization logic
- Session / token management
- Database migrations adding/removing columns
- API middleware (CORS, CSRF, rate limiting)
- Student data models or serializers
- Payment / billing logic
- Permission / role definitions

**HIGH files** (review with focus):
- API route handlers / controllers
- Data validation logic
- File upload handlers
- Search / query builders
- LLM prompt templates
- Email / notification senders

**MEDIUM files** (scan for regressions):
- UI components with form inputs
- State management changes
- Routing configuration
- Feature flag logic
- Configuration files

**LOW files** (quick verify):
- Styling / CSS changes
- Documentation updates
- Test files (verify they test the right thing)
- Comment-only changes

## Phase 2: Code Analysis

For each CRITICAL and HIGH file:

1. **Read the full diff** — not just changed lines, but surrounding context
2. **Trace data flow** — where does input come from? Where does output go?
3. **Check authorization** — is the current user authorized for this action?
4. **Verify validation** — is input validated server-side (not just client-side)?
5. **Look for missing checks** — what was removed? What's NOT there that should be?

### Key questions per file type:

**API endpoints:**
- Is there auth middleware on this route?
- Is the request body validated and typed?
- Are query parameters sanitized?
- Is the response filtered (no extra fields)?
- Is there rate limiting?

**Database changes:**
- Is the migration reversible?
- Are new columns nullable with defaults (safe deploy)?
- Is there an index on frequently queried columns?
- Are foreign keys properly constrained?

**Frontend forms:**
- Is there server-side validation (not just client-side)?
- Are file uploads restricted by type and size?
- Is user-generated content sanitized before rendering?

## Phase 3: Test Coverage

For every security-relevant change, verify:

- [ ] There is at least one test covering the happy path
- [ ] There is at least one test covering the error/rejection path
- [ ] Auth bypass attempts are tested (missing token, wrong role, different org)
- [ ] Input validation rejects known-bad inputs
- [ ] If a bug was fixed, there's a regression test

```bash
# Check if test files were modified alongside source files
git diff main...HEAD --name-only | grep -E "\.test\.|\.spec\.|__tests__"
```

## Phase 4: Blast Radius

Estimate the downstream impact of changes:

```bash
# Find all importers of changed files
for file in $(git diff main...HEAD --name-only); do
  echo "=== $file ==="
  grep -rn "$(basename $file .ts)\|$(basename $file .tsx)\|$(basename $file .py)" --include="*.ts" --include="*.tsx" --include="*.py" src/ app/ | grep -v "$file"
done
```

**Blast radius categories:**
- **Contained**: Change only affects the modified file
- **Module**: Change affects other files in the same feature/module
- **Cross-cutting**: Change affects multiple features (e.g., shared utility, middleware)
- **Platform**: Change affects all users/tenants (e.g., auth, database schema)

## Phase 5: Adversarial Modeling

Think like an attacker. For each CRITICAL/HIGH finding:

1. **Who benefits?** — Student cheating? Competitor? Random attacker?
2. **What's the attack vector?** — Direct API call? XSS? CSRF? Social engineering?
3. **What's the impact?** — Data leak? Privilege escalation? Service disruption?
4. **How detectable is it?** — Would logs catch it? Would users notice?
5. **What's the effort?** — Script kiddie? Skilled attacker? Insider?

### EdTech-specific attack scenarios:
- Student modifies their own grade via API manipulation
- Teacher accesses another school's student data
- Parent account escalates to teacher privileges
- Student extracts assessment answers from client-side code
- Attacker uses LLM integration to extract system prompts or student data

## Phase 6: Report Generation

Compile findings into a structured report per [reporting.md](reporting.md). Every finding must have:

1. Location (file:line)
2. Severity rating with justification
3. Description of the vulnerability
4. Proof of concept or attack scenario
5. Recommended fix
6. Blast radius estimate
