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
