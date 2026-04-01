# Auth Flow Review

Review authentication and authorization implementations for security vulnerabilities. Covers token management, session handling, role-based access control, OAuth/SSO flows, and multi-tenant isolation — tuned for EdTech platforms with complex role hierarchies (student, teacher, parent, admin, district admin).

## Quick Reference

| Auth Component | Risk Level | Common Vulnerabilities |
|---|---|---|
| **Token storage** | CRITICAL | Tokens in localStorage, no HttpOnly flag, missing Secure flag |
| **Session management** | CRITICAL | No expiry, missing rotation, fixation attacks |
| **Password handling** | CRITICAL | Weak hashing, plaintext storage, no rate limiting |
| **Role enforcement** | HIGH | Client-side only checks, missing middleware, privilege escalation |
| **OAuth/SSO** | HIGH | State parameter missing, redirect URI validation, token exchange flaws |
| **Multi-tenant isolation** | HIGH | Missing org scoping, cross-tenant data access |
| **MFA** | MEDIUM | Bypassable, missing for admin roles, recovery flow weaknesses |
| **API auth** | HIGH | Missing auth on endpoints, weak API key management |

## Decision Tree

```
START → Map the authentication architecture
  │
  ├─ How are users authenticated?
  │   ├─ Email/password → Check password hashing, storage, rate limiting
  │   ├─ OAuth/SSO → Check state param, redirect validation, token exchange
  │   ├─ Magic links → Check token expiry, single-use enforcement
  │   └─ API keys → Check rotation, scoping, transmission security
  │
  ├─ How are sessions managed?
  │   ├─ JWT → Check signing algorithm, expiry, refresh flow, revocation
  │   ├─ Server sessions → Check storage, fixation, rotation
  │   └─ Cookies → Check flags (HttpOnly, Secure, SameSite), domain scoping
  │
  ├─ How is authorization enforced?
  │   ├─ Role-based → Check middleware, server-side enforcement, role hierarchy
  │   ├─ Permission-based → Check granularity, default-deny, permission checks
  │   └─ Multi-tenant → Check org scoping on every data query
  │
  └─ What's the role hierarchy?
      └─ Map: Student → Teacher → School Admin → District Admin → Platform Admin
          Check: Can each role ONLY access what it should?
```

## Audit Phases

### Phase 1: Authentication Mechanism

```bash
# Find auth-related files
grep -rn "login\|signin\|sign.in\|authenticate\|password\|credential" --include="*.ts" --include="*.py" --include="*.js" src/ app/ lib/ routes/ controllers/

# Find token generation/validation
grep -rn "jwt\|jsonwebtoken\|sign(\|verify(\|token\|bearer" --include="*.ts" --include="*.py" --include="*.js" src/ app/ lib/

# Find OAuth/SSO configuration
grep -rn "oauth\|openid\|saml\|sso\|passport\|next-auth\|auth0\|clerk\|supabase.*auth" --include="*.ts" --include="*.py" --include="*.js" --include="*.env*" .

# Find Firebase Auth (common in EdTech)
grep -rn "getAuth\|signInWith\|onAuthStateChanged\|getIdToken\|firebase.*auth\|signInWithCustomToken" --include="*.ts" --include="*.tsx" src/

# Find iframe/LMS auth token injection (TED Ankara, Google Classroom, Canvas LTI)
grep -rn "postMessage\|iframe.*token\|iframe.*auth\|atob\|base64.*decode\|DATA_PARAM\|tedankara\|lti" --include="*.ts" --include="*.tsx" src/

# Find global auth state variables (mutable globals = risk)
grep -rn "let.*token\|let.*role\|let.*auth\|globalToken\|globalUserRole\|setUserRole\|setGlobalToken" --include="*.ts" --include="*.tsx" src/
```

**Check for:**

- [ ] **Password hashing**: bcrypt/scrypt/argon2 with appropriate cost factor (not MD5/SHA). If using Firebase Auth, password handling is delegated — verify Firebase project config instead
- [ ] **Salt**: Per-user random salt (not global or missing)
- [ ] **Rate limiting**: Login attempts limited per IP and per account
- [ ] **Account lockout**: Temporary lockout after failed attempts
- [ ] **Credential stuffing defense**: CAPTCHA or similar after suspicious activity
- [ ] **Password requirements**: Minimum length, breach database check
- [ ] **Firebase custom token flow**: If backend issues `customToken` for `signInWithCustomToken`, verify the backend validates the upstream auth (OAuth code, LMS token) before issuing it
- [ ] **Iframe token injection**: If auth data comes via URL params or `postMessage`, verify origin checking and token scope

### Phase 2: Token & Session Security

```bash
# Find token storage on client side
grep -rn "localStorage\|sessionStorage\|cookie" --include="*.ts" --include="*.tsx" --include="*.js" src/ | grep -i "token\|auth\|session\|jwt"

# Find token configuration
grep -rn "expiresIn\|maxAge\|expires\|ttl\|lifetime" --include="*.ts" --include="*.py" --include="*.js" src/ config/

# Find refresh token logic
grep -rn "refresh.*token\|token.*refresh\|rotate\|renewal" --include="*.ts" --include="*.py" src/ app/
```

**Check for:**

- [ ] **Token storage**: Not in localStorage (XSS accessible), prefer HttpOnly cookies
- [ ] **Token expiry**: Short-lived access tokens (15min-1hr), longer refresh tokens
- [ ] **Refresh rotation**: Refresh tokens rotated on use (detect token reuse)
- [ ] **Revocation**: Can tokens be invalidated server-side (logout, password change)?
- [ ] **Cookie flags**: HttpOnly, Secure, SameSite=Strict/Lax
- [ ] **JWT algorithm**: RS256/ES256 preferred over HS256, never "none"
- [ ] **JWT validation**: Signature verified, expiry checked, issuer validated

### Phase 3: Authorization & RBAC

```bash
# Find role definitions
grep -rn "role\|permission\|admin\|teacher\|student\|parent\|RBAC" --include="*.ts" --include="*.py" src/ types/ models/ middleware/

# Find auth middleware usage
grep -rn "authMiddleware\|requireAuth\|requireRole\|isAuthenticated\|protect\|guard" --include="*.ts" --include="*.py" src/ routes/ middleware/

# Find routes WITHOUT auth middleware
grep -rn "router\.\(get\|post\|put\|patch\|delete\)\|app\.\(get\|post\|put\|patch\|delete\)" --include="*.ts" --include="*.py" src/ routes/ | grep -v "auth\|middleware\|protect\|guard"
```

**Check for:**

- [ ] **Server-side enforcement**: All permission checks happen on the server (not just UI hiding)
- [ ] **Default deny**: Routes require auth by default, public routes explicitly marked
- [ ] **Role hierarchy respect**: Lower roles cannot access higher role endpoints
- [ ] **IDOR prevention**: Users cannot access resources by manipulating IDs
- [ ] **Horizontal authz**: User A cannot access User B's data at the same role level
- [ ] **Vertical authz**: Students cannot access teacher endpoints, teachers cannot access admin

### Phase 4: Multi-Tenant Isolation

```bash
# Find tenant/org scoping
grep -rn "orgId\|organizationId\|tenantId\|schoolId\|districtId" --include="*.ts" --include="*.py" src/ models/ queries/

# Find queries that might miss tenant scope
grep -rn "findAll\|find(\|findMany\|select.*from\|SELECT.*FROM" --include="*.ts" --include="*.py" src/ | grep -iv "orgId\|organizationId\|tenantId"
```

**Check for:**

- [ ] **Query scoping**: Every data query includes tenant/org filter
- [ ] **Middleware enforcement**: Tenant ID injected via middleware (not per-query)
- [ ] **Cache isolation**: Cache keys include tenant ID
- [ ] **File storage isolation**: Uploaded files scoped to tenant
- [ ] **Cross-tenant API calls**: Cannot access another org's data by changing headers

### Phase 5: EdTech-Specific Auth Patterns

| Pattern | Risk | Check |
|---|---|---|
| **Student impersonation** | Teachers viewing as student for debugging | Audit logged? Can students detect? Scoped correctly? |
| **Parent-student linking** | Parents accessing child's account | Verified relationship? Age-appropriate access? |
| **Class/roster access** | Teachers seeing only their students | Roster-based filtering? Year/term scoping? |
| **Assessment lockdown** | Students restricted during exams | Server-enforced? Can't bypass with DevTools? |
| **LTI integration** | External tool authentication | LTI signatures validated? Launch context verified? |
| **Shared devices** | Kiosk/lab computer usage | Session cleanup? Auto-logout? No persistent tokens? |
| **LMS iframe embedding** | App embedded in school LMS (TED, Canvas, etc.) | Token injected via URL param? Base64 decoded? Origin verified? localStorage persisted? |
| **Multi-auth-context** | Same app serves teacher standalone + student iframe + mobile webview | Token scope isolation? Role correctly set per context? Cross-context token leakage? |
| **OAuth callback → postMessage** | OAuth providers redirect to callback page that postMessages token to parent | Wildcard `"*"` origin? Token interceptable by embedding page? |

### Phase 6: Global Mutable Auth State (Frontend-Specific)

Many frontend apps store auth state in module-level `let` variables for header injection. Audit these carefully:

```bash
# Find global mutable auth variables
grep -rn "^let.*token\|^let.*role\|^let.*auth\|^let.*organizationId" --include="*.ts" --include="*.tsx" src/

# Find functions that mutate global auth state
grep -rn "export.*function.*set.*Token\|export.*function.*set.*Role\|export.*const.*set.*Token" --include="*.ts" src/

# Check if these setters are importable/callable from browser console
grep -rn "export.*setUserRole\|export.*setGlobalToken\|export.*setIframeAuthData" --include="*.ts" src/
```

**Check for:**

- [ ] Are global auth variables (`let globalToken`, `let globalUserRole`) exported and callable from DevTools?
- [ ] Can a user call `setUserRole("ADMIN")` from the browser console to escalate privileges?
- [ ] Does the backend independently validate the `UserRole` header, or does it trust the client?
- [ ] If role is a `let` variable, can two browser tabs interfere with each other's role?

## Red Flags — Immediate Escalation

- Passwords stored in plaintext or with MD5/SHA1
- JWT signed with "none" algorithm or HS256 with weak secret
- Tokens stored in localStorage
- No auth middleware on API routes handling student data
- Client-side only role checks with no server enforcement
- No rate limiting on login endpoint
- Refresh tokens that never expire and never rotate
- Missing tenant scoping on database queries
- Admin endpoints accessible without admin role verification
- Hard-coded credentials or API keys in source code
- Global mutable `let` variable for user role — callable via DevTools `setUserRole("ADMIN")`. If backend trusts `UserRole` header → privilege escalation
- Auth tokens passed as URL query parameters (visible in browser history, server logs, referrer headers)
- Base64-encoded auth data in URL params stored in localStorage without expiry
- `postMessage("*")` sending custom tokens from OAuth callback pages
- `ProtectedRoute` checking only `isAuthenticated` without role-based route guards — all authenticated users access all routes
- Firebase custom token issued without validating the upstream auth provider's response

## Output

Generate a structured report with:

1. Authentication architecture diagram (text-based)
2. Per-phase findings with severity ratings
3. Role hierarchy verification results
4. Multi-tenant isolation assessment
5. Remediation steps prioritized by risk

## Supporting Documents

- [patterns.md](patterns.md) — Common auth vulnerability patterns
- [reporting.md](reporting.md) — Report template
