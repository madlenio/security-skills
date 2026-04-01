# Common Compliance Anti-Patterns

## Pattern 1: No Consent Before Data Collection

```typescript
// VIOLATION: Collecting student data without consent mechanism
app.post("/api/students", async (req, res) => {
  const student = await Student.create(req.body); // No consent check
  await analytics.track("student_created", student); // Tracking without consent
  res.json(student);
});

// COMPLIANT: Consent check before processing
app.post("/api/students", async (req, res) => {
  if (!req.body.consentGiven || !req.body.consentTimestamp) {
    return res.status(400).json({ error: "Consent required before processing" });
  }
  const student = await Student.create({
    ...req.body,
    consentRecordId: await ConsentRecord.create({
      type: "data_processing",
      givenBy: req.user.id, // Parent/guardian for minors
      givenAt: new Date(),
      scope: "educational_services",
    }),
  });
  res.json(student);
});
```

## Pattern 2: No Data Deletion Capability

```typescript
// VIOLATION: No way to delete user data (GDPR Art. 17)
// Only "soft delete" that hides from UI but retains data
app.delete("/api/students/:id", async (req, res) => {
  await Student.update({ id: req.params.id }, { isActive: false }); // Data still exists
  res.json({ success: true });
});

// COMPLIANT: True deletion across all stores
app.delete("/api/students/:id", async (req, res) => {
  const studentId = req.params.id;
  await Promise.all([
    Student.destroy({ where: { id: studentId } }),
    ActivityLog.destroy({ where: { studentId } }),
    Assessment.anonymize({ where: { studentId } }), // Keep aggregate data, remove PII
    FileStorage.deleteUserFiles(studentId),
    Cache.invalidateUser(studentId),
    SearchIndex.removeUser(studentId),
  ]);
  await DeletionLog.create({ entityType: "student", entityId: studentId, deletedBy: req.user.id });
  res.json({ success: true });
});
```

## Pattern 3: Third-Party Data Sharing Without DPA

```typescript
// VIOLATION: Sending student data to analytics without data processing agreement
posthog.capture("quiz_completed", {
  studentEmail: student.email,
  studentName: student.name,
  score: quiz.score,
  schoolName: school.name,
});

// COMPLIANT: Anonymized analytics with DPA in place
posthog.capture("quiz_completed", {
  userId: anonymizeId(student.id), // One-way hash
  scoreRange: bucketScore(quiz.score), // "80-90" not "87"
  orgType: school.type, // "k12" not school name
});
```

## Pattern 4: Missing Data Retention Enforcement

```typescript
// VIOLATION: No retention policy, data lives forever
const createActivityLog = (data) => {
  return db.activityLogs.create(data); // Never cleaned up
};

// COMPLIANT: Retention policy with automated enforcement
const createActivityLog = (data) => {
  return db.activityLogs.create({
    ...data,
    retentionPolicy: "2_years",
    expiresAt: addYears(new Date(), 2),
  });
};

// Scheduled job
cron.schedule("0 2 * * *", async () => {
  const expired = await db.activityLogs.findAll({ where: { expiresAt: { [Op.lt]: new Date() } } });
  await db.activityLogs.destroy({ where: { id: expired.map(r => r.id) } });
  logger.info(`Purged ${expired.length} expired activity logs`);
});
```

## Pattern 5: Cross-Border Data Transfer Without Safeguards

```typescript
// VIOLATION: Turkish user data stored in US region without safeguards
const s3Config = {
  bucket: "student-uploads",
  region: "us-east-1", // All data goes to US regardless of user location
};

// COMPLIANT: Region-aware storage with transfer safeguards
const getStorageConfig = (user) => {
  if (user.country === "TR") {
    return { bucket: "student-uploads-tr", region: "eu-west-1" }; // KVKK compliance
  }
  if (user.country in EU_COUNTRIES) {
    return { bucket: "student-uploads-eu", region: "eu-west-1" }; // GDPR compliance
  }
  return { bucket: "student-uploads", region: "us-east-1" };
};
```

## Pattern 6: Child Data Without Parental Consent (COPPA)

```typescript
// VIOLATION: Under-13 user created without parental consent
app.post("/api/register", async (req, res) => {
  const user = await User.create(req.body); // No age check
  await sendWelcomeEmail(user.email); // Emailing a child without consent
  res.json(user);
});

// COMPLIANT: Age-gated registration with parental consent flow
app.post("/api/register", async (req, res) => {
  const age = calculateAge(req.body.dateOfBirth);

  if (age < 13) {
    const pendingUser = await PendingRegistration.create({
      ...req.body,
      requiresParentalConsent: true,
      consentRequestSentTo: req.body.parentEmail,
    });
    await sendParentalConsentRequest(req.body.parentEmail, pendingUser.id);
    return res.json({ status: "pending_parental_consent" });
  }

  const user = await User.create(req.body);
  res.json(user);
});
```
