# Student Data Audit

Scan codebases for student PII exposure risks, insecure data storage, compliance gaps, and data lifecycle violations. Purpose-built for EdTech applications handling sensitive educational records.

## Quick Reference

| Data Category | Sensitivity | Examples | Required Protection |
|---|---|---|---|
| **Direct PII** | CRITICAL | Full name, email, SSN, date of birth | Encryption at rest + in transit, access logging |
| **Educational Records** | HIGH | Grades, assessment scores, IEP/504 data, attendance | Role-based access, audit trail, retention policy |
| **Behavioral Data** | HIGH | Learning analytics, time-on-task, click patterns | Consent, anonymization for analytics, retention limits |
| **Account Data** | MEDIUM | Username, hashed password, role, org membership | Secure hashing, no plaintext, session management |
| **Usage Metadata** | LOW | Feature usage counts, UI preferences, locale | Aggregation OK, but watch for re-identification |

## Decision Tree

```
START → Identify all data models/schemas containing student information
  │
  ├─ Does the code store Direct PII?
  │   └─ YES → Check encryption, access controls, audit logging
  │   └─ Flag if: plaintext storage, logged in errors, sent to analytics
  │
  ├─ Does it transmit student data to external services?
  │   └─ YES → Check DPA agreements, data minimization, TLS enforcement
  │   └─ Flag if: sent to analytics/LLM without anonymization
  │
  ├─ Does it handle data from minors (under 13 / under 16)?
  │   └─ YES → COPPA/GDPR-K path: verify parental consent flow
  │   └─ Flag if: no age verification, no consent records
  │
  ├─ Does it implement data deletion/export?
  │   └─ NO → Flag: GDPR Art.17 right to erasure likely required
  │   └─ YES → Verify completeness (all stores, backups, logs, caches)
  │
  └─ Does it share data across organizational boundaries?
      └─ YES → Check tenant isolation, verify no cross-org leakage
```

## Audit Phases

### Phase 1: Data Inventory

Map every location where student data is stored, processed, or transmitted:

```bash
# Find data models/schemas
grep -rn "student\|pupil\|learner\|grade\|score\|assessment" --include="*.ts" --include="*.py" --include="*.rb" --include="*.java" src/ app/ lib/

# Find database migrations mentioning student fields
grep -rn "email\|name\|birth\|ssn\|grade\|score" --include="*.sql" --include="*.rb" migrations/ db/

# Find API endpoints exposing student data
grep -rn "student\|profile\|grade\|roster\|enrollment" --include="*.ts" --include="*.py" routes/ controllers/ api/

# Find environment variables that may contain student data paths
grep -rn "STUDENT\|PII\|RECORD\|GRADE" .env* docker-compose* *.yml
```

### Phase 2: Storage Security

For each data location found in Phase 1:

- [ ] **Encryption at rest**: Is sensitive data encrypted in the database?
- [ ] **Encryption in transit**: Are all API calls over TLS? Any HTTP fallbacks?
- [ ] **Access controls**: Who can read/write student records? Is it role-enforced server-side?
- [ ] **Audit logging**: Are reads/writes to student data logged with actor + timestamp?
- [ ] **Backup security**: Are database backups encrypted? Who has access?

### Phase 3: Data Flow Analysis

Trace student data through the application:

- [ ] **Frontend → Backend**: Is PII sent in URL params (logged in server access logs)?
- [ ] **Backend → Database**: Are queries parameterized (no SQL injection)?
- [ ] **Backend → External Services**: Which 3rd parties receive student data?
- [ ] **Backend → Logs**: Is PII stripped before logging?
- [ ] **Backend → Analytics**: Is student data anonymized before tracking?
- [ ] **Backend → AI/LLM**: Is student PII sent in prompts? Can it leak in completions?
- [ ] **Backend → Cache**: Is cached student data scoped to the correct tenant/user?

### Phase 4: Compliance Check

| Regulation | Key Requirements | Check |
|---|---|---|
| **FERPA** (US) | Written consent for disclosure, parent access rights, legitimate educational interest | Directory information policy, consent records, access logging |
| **COPPA** (US) | Parental consent for under-13, data minimization, deletion on request | Age gates, consent flows, retention limits |
| **GDPR** (EU) | Lawful basis, data minimization, right to erasure, DPIAs | Privacy policy, consent management, deletion endpoints |
| **KVKK** (Turkey) | Explicit consent, data controller registration, cross-border transfer rules | VERBIS registration, consent records, data localization |

### Phase 5: Lifecycle Audit

- [ ] **Collection**: Is there a privacy notice at data collection points?
- [ ] **Retention**: Are there defined retention periods? Are they enforced?
- [ ] **Deletion**: Can users request data deletion? Is it complete (all stores)?
- [ ] **Export**: Can users export their data (GDPR portability)?
- [ ] **Breach response**: Is there an incident response plan for data breaches?

## Red Flags — Immediate Escalation

- Student emails/names in application logs at INFO/DEBUG level
- PII in URL query parameters (`/api/students?name=John&grade=A`)
- Student data sent to analytics platforms without anonymization
- Missing `org_id` / tenant scoping on student data queries
- Hardcoded test student data with real-looking PII
- No retention policy — student data stored indefinitely
- Student data in client-side localStorage or cookies
- API endpoints returning more student fields than needed (no field filtering)
- LLM prompts containing student names, grades, or other PII

## Output

Generate a structured report per [reporting.md](reporting.md) with:

1. Data inventory map
2. Finding severity ratings (CRITICAL / HIGH / MEDIUM / LOW / INFO)
3. Compliance gap analysis
4. Remediation recommendations with priority ordering

## Supporting Documents

- [patterns.md](patterns.md) — Common student data exposure patterns with code examples
- [reporting.md](reporting.md) — Report template and severity definitions
