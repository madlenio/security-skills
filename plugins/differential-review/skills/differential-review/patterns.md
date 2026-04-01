# Common Vulnerability Patterns

## Authentication & Authorization

### Missing auth middleware
```typescript
// VULNERABLE: No auth check
router.get("/api/students/:id", async (req, res) => {
  const student = await db.students.findById(req.params.id);
  res.json(student);
});

// FIXED: Auth middleware + authorization check
router.get("/api/students/:id", authMiddleware, async (req, res) => {
  const student = await db.students.findById(req.params.id);
  if (student.orgId !== req.user.orgId) return res.status(403).json({ error: "Forbidden" });
  res.json(student);
});
```

### Client-side only permission checks
```typescript
// VULNERABLE: Only checking role on frontend
{user.role === "teacher" && <GradeEditor />}

// Server has no corresponding check — student can call the API directly
// REQUIRED: Server-side role verification on the grade update endpoint
```

### IDOR (Insecure Direct Object Reference)
```typescript
// VULNERABLE: User controls the ID, no ownership check
app.get("/api/assignments/:id", async (req, res) => {
  return db.assignments.findById(req.params.id); // Any user can access any assignment
});

// FIXED: Scope to current user's organization
app.get("/api/assignments/:id", authMiddleware, async (req, res) => {
  return db.assignments.findOne({ id: req.params.id, orgId: req.user.orgId });
});
```

## Data Exposure

### PII in logs
```typescript
// VULNERABLE: Student data in logs
logger.info(`Student ${student.name} (${student.email}) submitted assignment ${assignmentId}`);

// FIXED: Use IDs only
logger.info(`Student ${student.id} submitted assignment ${assignmentId}`);
```

### Over-fetching in API responses
```typescript
// VULNERABLE: Returns all fields including sensitive ones
res.json(await db.students.findById(id));

// FIXED: Select only needed fields
res.json(await db.students.findById(id).select("id name displayName grade"));
```

### PII in URL parameters
```typescript
// VULNERABLE: PII in URL (logged in access logs, browser history, referrer headers)
fetch(`/api/search?studentName=${name}&grade=${grade}`);

// FIXED: Use POST body for sensitive searches
fetch("/api/search", { method: "POST", body: JSON.stringify({ studentName: name, grade }) });
```

## Cross-Site Scripting (XSS)

### Unescaped user content in React
```tsx
// VULNERABLE: Direct HTML rendering of user content
<div dangerouslySetInnerHTML={{ __html: studentComment }} />

// FIXED: Use a sanitization library
import DOMPurify from "dompurify";
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(studentComment) }} />

// BEST: Don't use dangerouslySetInnerHTML at all — use a markdown renderer with sanitization
```

### LLM output rendered as HTML
```tsx
// VULNERABLE: LLM output may contain script tags or event handlers
<div dangerouslySetInnerHTML={{ __html: llmResponse }} />

// FIXED: Sanitize LLM output before rendering
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(llmResponse) }} />
```

## SQL Injection

### String interpolation in queries
```typescript
// VULNERABLE: Direct interpolation
const query = `SELECT * FROM students WHERE name = '${req.query.name}'`;

// FIXED: Parameterized query
const query = `SELECT * FROM students WHERE name = $1`;
const result = await db.query(query, [req.query.name]);
```

## Multi-Tenant Isolation

### Missing tenant scoping
```typescript
// VULNERABLE: No org filter — returns all orgs' data
const students = await db.students.find({ grade: "A" });

// FIXED: Always scope to current org
const students = await db.students.find({ grade: "A", orgId: req.user.orgId });
```

### Cache key collision
```typescript
// VULNERABLE: Cache key without org scope
cache.set(`students:${grade}`, data);

// FIXED: Include org in cache key
cache.set(`students:${orgId}:${grade}`, data);
```

## Assessment Integrity

### Client-side answer exposure
```typescript
// VULNERABLE: Sending correct answers to the client
const quiz = await db.quizzes.findById(id);
res.json(quiz); // Includes quiz.answers

// FIXED: Strip answers in student-facing endpoints
const { answers, ...quizWithoutAnswers } = quiz;
res.json(quizWithoutAnswers);
```

### Predictable assessment IDs
```typescript
// VULNERABLE: Sequential IDs allow enumeration
const quiz = await db.quizzes.findById(parseInt(req.params.id)); // /quiz/1, /quiz/2, /quiz/3

// FIXED: Use UUIDs
const quiz = await db.quizzes.findById(req.params.uuid); // /quiz/a3f7b2c1-...
```
