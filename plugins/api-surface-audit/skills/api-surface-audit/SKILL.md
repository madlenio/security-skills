# API Surface Audit

Map and audit all exposed API endpoints for authentication, authorization, input validation, rate limiting, and information disclosure. Purpose-built for EdTech platforms where API security directly protects student data.

## Quick Reference

| Risk Category | Severity | What to Check |
|---|---|---|
| **Unauthenticated endpoints** | CRITICAL | Any endpoint without auth that returns or modifies data |
| **Missing authorization** | CRITICAL | Auth present but no role/ownership check |
| **No input validation** | HIGH | Endpoints accepting unvalidated user input |
| **No rate limiting** | HIGH | Endpoints vulnerable to brute force or abuse |
| **Information disclosure** | MEDIUM | Verbose errors, stack traces, internal IDs in responses |
| **Missing CORS policy** | MEDIUM | Overly permissive cross-origin access |
| **No request size limits** | MEDIUM | Endpoints accepting unbounded payloads |

## Decision Tree

```
START → Enumerate all API endpoints
  │
  ├─ For each endpoint:
  │   ├─ Is authentication required?
  │   │   └─ NO → Flag as CRITICAL (unless intentionally public)
  │   │
  │   ├─ Is authorization checked (role + ownership)?
  │   │   └─ NO → Flag as CRITICAL
  │   │
  │   ├─ Is input validated and typed?
  │   │   └─ NO → Flag as HIGH
  │   │
  │   ├─ Is there rate limiting?
  │   │   └─ NO → Flag as HIGH for auth endpoints, MEDIUM for others
  │   │
  │   ├─ Does the response leak sensitive data?
  │   │   └─ YES → Flag based on data sensitivity
  │   │
  │   └─ Is the endpoint documented?
  │       └─ NO → Flag as INFO (shadow API risk)
  │
  └─ Generate endpoint inventory with risk ratings
```

## Audit Phases

### Phase 1: Endpoint Discovery

Map every API endpoint in the codebase:

```bash
# Express/Node.js routes
grep -rn "router\.\(get\|post\|put\|patch\|delete\|all\)\|app\.\(get\|post\|put\|patch\|delete\|all\)" --include="*.ts" --include="*.js" src/ routes/ app/ api/

# Next.js API routes
find . -path "*/api/*" -name "*.ts" -o -name "*.js" | grep -v node_modules | grep -v ".d.ts"

# Django/Python routes
grep -rn "path(\|url(\|@app\.\(get\|post\|put\|delete\)\|@router\." --include="*.py" .

# FastAPI routes
grep -rn "@app\.\|@router\." --include="*.py" . | grep -E "(get|post|put|patch|delete)\("

# OpenAPI/Swagger definitions
find . -name "*.yaml" -o -name "*.yml" -o -name "*.json" | xargs grep -l "openapi\|swagger" 2>/dev/null
```

**Build an endpoint inventory table:**

| Method | Path | Auth | Roles | Rate Limited | Validated | Notes |
|---|---|---|---|---|---|---|
| GET | /api/students | YES/NO | [roles] | YES/NO | YES/NO | [notes] |

### Phase 2: Authentication Audit

For each endpoint, verify authentication:

```bash
# Find middleware chain for each route
grep -rn "middleware\|authMiddleware\|requireAuth\|protect\|isAuthenticated\|guard" --include="*.ts" --include="*.py" src/ routes/ middleware/

# Find routes that explicitly skip auth
grep -rn "public\|noAuth\|skipAuth\|anonymous\|unprotected" --include="*.ts" --include="*.py" src/ routes/
```

**Check for:**

- [ ] **Auth middleware coverage**: Is every non-public endpoint protected?
- [ ] **Auth bypass routes**: Are public routes intentionally and minimally public?
- [ ] **Token validation**: Are tokens validated on every request (not cached stale)?
- [ ] **Auth error handling**: Do auth failures return 401 (not 200 with error message)?

### Phase 3: Authorization Audit

For each authenticated endpoint, verify authorization:

```bash
# Find endpoints with auth but no role/permission check
grep -rn "router\.\(get\|post\|put\|delete\)" --include="*.ts" src/ routes/ | grep "auth" | grep -v "role\|permission\|admin\|teacher\|owner"

# Find ownership checks (IDOR prevention)
grep -rn "req\.user\.id\|req\.user\.orgId\|currentUser\|userId.*===\|orgId.*===" --include="*.ts" --include="*.py" src/ routes/ controllers/
```

**Check for:**

- [ ] **Role-based access**: Endpoints enforce role requirements (student vs teacher vs admin)
- [ ] **Ownership verification**: Users can only access their own resources (IDOR prevention)
- [ ] **Tenant scoping**: Multi-tenant queries always include org_id filter
- [ ] **Principle of least privilege**: Endpoints return only what the user's role permits

### Phase 4: Input Validation Audit

```bash
# Find request body parsing without validation
grep -rn "req\.body\|request\.body\|req\.params\|req\.query" --include="*.ts" --include="*.py" src/ routes/ controllers/ | grep -v "validate\|schema\|zod\|joi\|yup\|class-validator"

# Find validation libraries in use
grep -rn "zod\|joi\|yup\|class-validator\|express-validator\|ajv" package.json requirements.txt

# Find file upload endpoints
grep -rn "multer\|upload\|multipart\|formidable\|busboy" --include="*.ts" --include="*.py" src/ routes/
```

**Check for:**

- [ ] **Schema validation**: Request bodies validated against a schema (Zod, Joi, etc.)
- [ ] **Type coercion**: Parameters properly typed (not trusting string→number conversion)
- [ ] **SQL injection**: Queries use parameterized statements
- [ ] **NoSQL injection**: MongoDB queries don't accept raw user objects
- [ ] **File upload limits**: Type whitelist, size limits, malware scanning
- [ ] **Path traversal**: File operations sanitize user-provided paths

### Phase 5: Rate Limiting & Abuse Prevention

```bash
# Find rate limiting configuration
grep -rn "rateLimit\|rate.limit\|throttle\|limiter\|slowDown" --include="*.ts" --include="*.py" --include="*.js" src/ middleware/ config/

# Find sensitive endpoints that need rate limiting
grep -rn "login\|register\|reset.*password\|forgot.*password\|verify\|otp\|token" --include="*.ts" --include="*.py" src/ routes/
```

**Check for:**

- [ ] **Auth endpoints**: Login, register, password reset — strict rate limits
- [ ] **Search endpoints**: Prevent data scraping via rapid queries
- [ ] **Export endpoints**: Limit bulk data extraction
- [ ] **LLM endpoints**: Token/cost-based rate limits
- [ ] **Per-user vs per-IP**: Both should be applied
- [ ] **Response headers**: Rate limit headers (X-RateLimit-*) for client awareness

### Phase 6: Response Security

```bash
# Find error handling that might leak info
grep -rn "stack\|stackTrace\|err\.message\|error\.message\|console\.error" --include="*.ts" --include="*.py" src/ routes/ controllers/ | grep -i "res\.\|response\.\|json("

# Find security headers
grep -rn "helmet\|cors\|X-Content-Type\|X-Frame-Options\|Content-Security-Policy\|Strict-Transport" --include="*.ts" --include="*.py" --include="*.js" src/ config/ middleware/

# Check CORS configuration
grep -rn "cors\|Access-Control-Allow-Origin\|allowedOrigins" --include="*.ts" --include="*.py" --include="*.js" src/ config/
```

**Check for:**

- [ ] **Error sanitization**: No stack traces or internal details in production responses
- [ ] **Response filtering**: No extra fields beyond what the client needs
- [ ] **Security headers**: HSTS, X-Content-Type-Options, X-Frame-Options, CSP
- [ ] **CORS policy**: Restrictive origin whitelist (not `*`)
- [ ] **Sensitive data in responses**: No tokens, passwords, internal IDs exposed

## Red Flags — Immediate Escalation

- API endpoints returning student data without authentication
- Admin endpoints accessible to non-admin roles
- No input validation on endpoints accepting user content
- CORS set to `Access-Control-Allow-Origin: *` in production
- Stack traces or database errors returned in API responses
- No rate limiting on login or password reset endpoints
- File upload endpoints with no type/size restrictions
- GraphQL introspection enabled in production
- API keys or secrets in response bodies
- Endpoints accepting and processing unbounded arrays or payloads

## Output

Generate a structured report with:

1. Complete endpoint inventory with risk ratings
2. Authentication coverage map (protected vs unprotected)
3. Authorization matrix (role × endpoint)
4. Input validation coverage
5. Rate limiting coverage
6. Remediation steps prioritized by risk

## Supporting Documents

- [patterns.md](patterns.md) — Common API security anti-patterns
- [reporting.md](reporting.md) — API audit report template
