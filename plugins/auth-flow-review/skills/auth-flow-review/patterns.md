# Common Auth Vulnerability Patterns

## Pattern 1: JWT with Weak Configuration

```typescript
// VULNERABLE: Weak secret, no expiry, algorithm not enforced
const token = jwt.sign({ userId: user.id, role: user.role }, "secret123");

// FIXED: Strong secret, short expiry, explicit algorithm
const token = jwt.sign(
  { sub: user.id, role: user.role, orgId: user.orgId },
  process.env.JWT_SECRET, // 256+ bit random secret
  { algorithm: "RS256", expiresIn: "15m", issuer: "madlen.io" }
);

// VULNERABLE: Not verifying algorithm (allows "none" attack)
const decoded = jwt.verify(token, secret);

// FIXED: Explicit algorithm verification
const decoded = jwt.verify(token, publicKey, { algorithms: ["RS256"], issuer: "madlen.io" });
```

## Pattern 2: Token Stored in localStorage

```typescript
// VULNERABLE: XSS can steal the token
localStorage.setItem("authToken", response.data.token);

// On every request:
headers: { Authorization: `Bearer ${localStorage.getItem("authToken")}` }

// FIXED: HttpOnly cookie set by server
// Server:
res.cookie("authToken", token, {
  httpOnly: true,    // JavaScript can't access
  secure: true,      // HTTPS only
  sameSite: "strict", // CSRF protection
  maxAge: 15 * 60 * 1000, // 15 minutes
});
```

## Pattern 3: Missing Auth Middleware on Sensitive Routes

```typescript
// VULNERABLE: Student data endpoint with no auth
router.get("/api/students/:id/grades", async (req, res) => {
  const grades = await Grade.findAll({ where: { studentId: req.params.id } });
  res.json(grades); // Anyone can access any student's grades
});

// FIXED: Auth + authorization middleware chain
router.get("/api/students/:id/grades",
  authMiddleware,              // Verify identity
  requireRole(["teacher", "admin"]), // Verify role
  requireOrgAccess,            // Verify same organization
  async (req, res) => {
    const grades = await Grade.findAll({
      where: { studentId: req.params.id, orgId: req.user.orgId },
    });
    res.json(grades);
  }
);
```

## Pattern 4: Client-Side Role Check Without Server Enforcement

```tsx
// VULNERABLE: Only UI hides the feature, API is unprotected
{user.role === "admin" && <AdminPanel />}

// The API endpoint has no role check:
router.delete("/api/users/:id", authMiddleware, async (req, res) => {
  await User.destroy({ where: { id: req.params.id } }); // Any authenticated user can delete
});

// FIXED: Server-side role enforcement
router.delete("/api/users/:id", authMiddleware, requireRole("admin"), async (req, res) => {
  await User.destroy({ where: { id: req.params.id, orgId: req.user.orgId } });
});
```

## Pattern 5: No Rate Limiting on Login

```typescript
// VULNERABLE: Unlimited login attempts
router.post("/api/login", async (req, res) => {
  const user = await User.findByEmail(req.body.email);
  if (!user || !await bcrypt.compare(req.body.password, user.passwordHash)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  res.json({ token: generateToken(user) });
});

// FIXED: Rate limiting + account lockout
router.post("/api/login",
  rateLimit({ windowMs: 15 * 60 * 1000, max: 5, keyGenerator: (req) => req.body.email }),
  rateLimit({ windowMs: 15 * 60 * 1000, max: 20, keyGenerator: (req) => req.ip }),
  async (req, res) => {
    const user = await User.findByEmail(req.body.email);
    if (user?.lockoutUntil > new Date()) {
      return res.status(423).json({ error: "Account temporarily locked" });
    }
    // ... auth logic with failed attempt counting
  }
);
```

## Pattern 6: OAuth State Parameter Missing

```typescript
// VULNERABLE: No state parameter (CSRF on OAuth callback)
const authUrl = `https://accounts.google.com/o/oauth2/auth?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code`;

// FIXED: Random state parameter verified on callback
const state = crypto.randomBytes(32).toString("hex");
req.session.oauthState = state;
const authUrl = `https://accounts.google.com/o/oauth2/auth?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&state=${state}`;

// On callback:
if (req.query.state !== req.session.oauthState) {
  return res.status(403).json({ error: "Invalid state parameter" });
}
```

## Pattern 7: Refresh Token Without Rotation

```typescript
// VULNERABLE: Same refresh token used indefinitely
app.post("/api/refresh", async (req, res) => {
  const decoded = jwt.verify(req.body.refreshToken, REFRESH_SECRET);
  const newAccessToken = generateAccessToken(decoded.userId);
  res.json({ accessToken: newAccessToken }); // Same refresh token stays valid forever
});

// FIXED: Rotate refresh token on every use
app.post("/api/refresh", async (req, res) => {
  const decoded = jwt.verify(req.body.refreshToken, REFRESH_SECRET);
  const storedToken = await RefreshToken.findOne({ token: req.body.refreshToken });

  if (!storedToken || storedToken.revoked) {
    // Token reuse detected — revoke entire family
    await RefreshToken.revokeFamily(decoded.familyId);
    return res.status(401).json({ error: "Token reuse detected" });
  }

  // Rotate: invalidate old, issue new
  await storedToken.update({ revoked: true });
  const newRefreshToken = await RefreshToken.create({ userId: decoded.userId, familyId: decoded.familyId });
  const newAccessToken = generateAccessToken(decoded.userId);

  res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken.token });
});
```

## Pattern 8: Global Mutable Role Variable (Client-Side Privilege Escalation)

```typescript
// VULNERABLE: Role stored as a module-level let, exported setter callable from console
let globalUserRole: string = "TEACHER";

export const setUserRole = (userRole: string) => {
  globalUserRole = userRole;
};

// In axios interceptor, this role is sent as a header:
headers: { UserRole: globalUserRole }

// ATTACK: Open DevTools → Console:
// import { setUserRole } from './axiosConfig';  // If bundler exposes
// Or find the module in webpack/vite's module registry and call setUserRole("ADMIN")

// REQUIRED: Backend must NEVER trust the UserRole header for authorization decisions.
// The role should be derived server-side from the authenticated token:
// Backend:
const userRole = await getUserRoleFromToken(req.headers.authorization);
// NOT: const userRole = req.headers["userrole"]; ← attacker-controlled
```

## Pattern 9: Base64 Auth Data in URL Parameters

```typescript
// VULNERABLE: Auth tokens encoded in URL query params
// URL: /iframe/tool?tedankaradata=eyJhcGlfdG9rZW4iOiJzZWNyZXQxMjMiLCJvcmdfaWQiOjF9

const url = new URL(window.location.href);
const dataParam = url.searchParams.get("tedankaradata");
const decoded = JSON.parse(atob(dataParam)); // { api_token: "secret123", org_id: 1 }

// RISKS:
// 1. URL visible in browser history (persists after session)
// 2. URL logged in web server access logs
// 3. URL leaked via Referrer header to external resources
// 4. URL visible in browser's address bar (shoulder surfing)
// 5. URL shared accidentally via screenshots or copy-paste

// PARTIAL MITIGATION (Madlen pattern): Remove from URL after reading
if (url.searchParams.has("tedankaradata")) {
  url.searchParams.delete("tedankaradata");
  window.history.replaceState(null, document.title, url.toString());
}
// ✅ Good — removes from URL bar and future history
// ❌ But: already in server logs, already in browser's visited URL history

// BETTER: Use POST request to inject auth, or use a one-time code
// that's exchanged for a token server-side (like OAuth authorization code flow)
```

## Pattern 10: ProtectedRoute Without Role-Based Guards

```tsx
// VULNERABLE: Only checks if user is authenticated, not their role
const ProtectedRoute = ({ children }) => {
  const isAuthenticated = useAppSelector((state) => state.user.isAuthenticated);
  if (!isAuthenticated) return <Navigate to="/login" />;
  return <>{children}</>;  // Any authenticated user can access ANY route
};

// A student who is authenticated can navigate to /admin/settings
// Frontend route protection is defense-in-depth — backend must enforce too

// IMPROVED: Role-based route protection (still requires backend enforcement)
const ProtectedRoute = ({ children, requiredRoles }) => {
  const { isAuthenticated, role } = useAppSelector((state) => state.user);
  if (!isAuthenticated) return <Navigate to="/login" />;
  if (requiredRoles && !requiredRoles.includes(role)) return <Navigate to="/unauthorized" />;
  return <>{children}</>;
};

// Usage:
<Route path="/admin/*" element={
  <ProtectedRoute requiredRoles={["ADMIN"]}>
    <AdminPanel />
  </ProtectedRoute>
} />
```

## Pattern 11: LMS Iframe Token Chain with Context Confusion

```typescript
// VULNERABLE: Multiple auth contexts sharing a single global token variable
// Standalone teacher session → sets globalToken = teacherFirebaseToken
// Iframe student chat → sets globalToken = studentScopedToken
// If routing changes without clearing → stale token from wrong context

// Token resolution chain:
const activeToken = getGlobalToken()           // Could be teacher token
  || iframeAuthData.accessToken                // TED Ankara iframe token
  || iframeAuthData.apiToken                   // TED Ankara API token
  || null;

// RISK: If a teacher opens a student-chat-embedded iframe in a new tab,
// the global teacher token may be used instead of the student token,
// giving the student chat teacher-level API access

// MITIGATION: Clear query cache and auth state on context switch
// (Madlen does this via queryClient.clear() on auth context change)
// Plus: Backend should validate token scope matches the endpoint
```
