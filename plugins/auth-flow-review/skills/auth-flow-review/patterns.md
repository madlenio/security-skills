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
