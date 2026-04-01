# EdTech Compliance Scanner

Automated compliance checklist scanning for FERPA, COPPA, GDPR, and KVKK. Maps codebase practices against regulatory requirements and identifies gaps before they become legal liabilities.

## Quick Reference

| Regulation | Jurisdiction | Key Focus | Applies When |
|---|---|---|---|
| **FERPA** | United States | Student education records, directory info, parental rights | Any US school/university data |
| **COPPA** | United States | Children under 13, parental consent, data minimization | Users may be under 13 |
| **GDPR** | European Union | Lawful basis, data subject rights, DPIAs, breach notification | EU users or data processing |
| **KVKK** | Turkey | Explicit consent, VERBIS registration, data localization | Turkish users or data processing |

## Decision Tree

```
START → Determine which regulations apply
  │
  ├─ Does the app serve US schools/universities?
  │   └─ YES → FERPA applies
  │
  ├─ Could any users be under 13?
  │   └─ YES → COPPA applies (strongest child protections)
  │
  ├─ Are there EU users or is EU data processed?
  │   └─ YES → GDPR applies
  │
  ├─ Are there Turkish users or is Turkish data processed?
  │   └─ YES → KVKK applies
  │
  └─ For each applicable regulation → Run the corresponding checklist below
```

## FERPA Compliance Checklist

The Family Educational Rights and Privacy Act protects student education records.

### Consent & Disclosure
- [ ] **Written consent**: Is written consent obtained before disclosing student records to third parties?
- [ ] **Directory information policy**: Is there a published policy defining what constitutes directory information?
- [ ] **Legitimate educational interest**: Are access controls based on legitimate educational interest?
- [ ] **Annual notification**: Are parents/students notified annually of their FERPA rights?

### Technical Controls
- [ ] **Access logging**: Are all accesses to student education records logged with actor + timestamp?
- [ ] **Role-based access**: Is access to records restricted by role (teacher, admin, parent)?
- [ ] **Data sharing agreements**: Are there signed agreements with all third parties receiving student data?
- [ ] **De-identification**: Is student data de-identified before use in research/analytics?

### Code-Level Checks
```bash
# Find third-party data sharing points
grep -rn "fetch\|axios\|http\.\|request\(" --include="*.ts" --include="*.js" src/ | grep -iv "localhost\|internal\|self"

# Find data export/download endpoints
grep -rn "export\|download\|csv\|xlsx\|pdf" --include="*.ts" --include="*.py" src/ routes/ controllers/

# Check for access logging on student data endpoints
grep -rn "audit\|log.*access\|track.*read" --include="*.ts" --include="*.py" src/ middleware/
```

## COPPA Compliance Checklist

The Children's Online Privacy Protection Act requires verifiable parental consent for children under 13.

### Consent & Age Verification
- [ ] **Age gate**: Is there a mechanism to determine if users are under 13?
- [ ] **Parental consent flow**: Is verifiable parental consent obtained before collecting data from under-13 users?
- [ ] **Consent records**: Are consent records stored and auditable?
- [ ] **Consent withdrawal**: Can parents revoke consent and request data deletion?

### Data Minimization
- [ ] **Collection limitation**: Is data collection limited to what's necessary for the activity?
- [ ] **No behavioral advertising**: Is behavioral/targeted advertising disabled for child users?
- [ ] **Third-party restrictions**: Are third parties prohibited from collecting child data?
- [ ] **Retention limits**: Is child data deleted when no longer needed for its original purpose?

### Code-Level Checks
```bash
# Find age-related logic
grep -rn "age\|birth\|dob\|date_of_birth\|minor\|child\|under.13\|under_13" --include="*.ts" --include="*.py" src/

# Find consent-related logic
grep -rn "consent\|parental\|guardian\|opt.in\|opt.out\|agree" --include="*.ts" --include="*.py" src/

# Find tracking/analytics that might affect children
grep -rn "track\|analytics\|pixel\|beacon\|fingerprint" --include="*.ts" --include="*.js" src/
```

## GDPR Compliance Checklist

The General Data Protection Regulation requires lawful basis, transparency, and data subject rights.

### Lawful Basis & Transparency
- [ ] **Privacy policy**: Is there a clear, accessible privacy policy?
- [ ] **Lawful basis documented**: Is the lawful basis for each processing activity documented?
- [ ] **Consent management**: For consent-based processing, is consent freely given, specific, informed, and unambiguous?
- [ ] **Cookie consent**: Is there a cookie consent mechanism (not just a notice)?

### Data Subject Rights
- [ ] **Right to access (Art. 15)**: Can users request a copy of their data?
- [ ] **Right to rectification (Art. 16)**: Can users correct inaccurate data?
- [ ] **Right to erasure (Art. 17)**: Can users request data deletion?
- [ ] **Right to portability (Art. 20)**: Can users export their data in a structured format?
- [ ] **Right to object (Art. 21)**: Can users object to processing?

### Technical Measures
- [ ] **Data Protection Impact Assessment**: Is there a DPIA for high-risk processing?
- [ ] **Privacy by design**: Is data protection considered from the design phase?
- [ ] **Breach notification**: Is there a process to notify authorities within 72 hours?
- [ ] **Data processing agreements**: Are there DPAs with all processors?
- [ ] **Cross-border transfers**: Are adequate safeguards in place for international transfers?

### Code-Level Checks
```bash
# Find data deletion endpoints
grep -rn "delete\|destroy\|remove\|purge\|erase" --include="*.ts" --include="*.py" src/ routes/ | grep -i "user\|student\|account\|profile\|data"

# Find data export/portability endpoints
grep -rn "export\|download\|portability" --include="*.ts" --include="*.py" src/ routes/

# Find cross-border transfer indicators
grep -rn "region\|aws\|gcp\|azure\|s3\|bucket\|cdn\|cloudfront" --include="*.ts" --include="*.yml" --include="*.env*" .
```

## KVKK Compliance Checklist

Kisisel Verilerin Korunmasi Kanunu — Turkey's data protection law, modeled after GDPR with local requirements.

### Registration & Consent
- [ ] **VERBIS registration**: Is the data controller registered with VERBIS (Data Controllers Registry)?
- [ ] **Explicit consent (Acik Riza)**: Is explicit consent obtained for processing personal data?
- [ ] **Consent language**: Is consent provided in Turkish for Turkish users?
- [ ] **Processing conditions**: Is processing based on one of the lawful conditions in Art. 5?

### Data Localization & Transfer
- [ ] **Data localization**: Is personal data of Turkish citizens stored in Turkey or in approved jurisdictions?
- [ ] **Cross-border approval**: For international transfers, is there Board approval or adequate protection?
- [ ] **Binding corporate rules**: For intra-group transfers, are binding corporate rules in place?

### Technical Controls
- [ ] **Data security (Art. 12)**: Are appropriate technical and organizational measures in place?
- [ ] **Breach notification**: Is there a process to notify the Board and data subjects of breaches?
- [ ] **Data retention policy**: Are retention periods defined and enforced?
- [ ] **Destruction policy**: Is there a documented personal data destruction policy?

### Code-Level Checks
```bash
# Find data storage locations
grep -rn "DATABASE_URL\|MONGO_URI\|REDIS_URL\|S3_BUCKET\|STORAGE" --include="*.env*" --include="*.yml" --include="*.ts" .

# Find localization/region configuration
grep -rn "region\|locale\|country\|tr_TR\|tr-TR\|turkey\|istanbul" --include="*.ts" --include="*.yml" --include="*.env*" .

# Find consent-related UI components
grep -rn "consent\|riza\|onay\|kvkk\|aydinlatma" --include="*.ts" --include="*.tsx" src/
```

## Red Flags — Immediate Escalation

- No privacy policy or it hasn't been updated in 12+ months
- Student data sent to third parties without data processing agreements
- No age verification when platform may serve children under 13
- No data deletion capability (GDPR Art. 17 violation)
- Personal data stored outside approved jurisdictions without legal basis
- No breach notification process documented
- Analytics tracking enabled for child users without parental consent
- No VERBIS registration for Turkish operations

## Output

Generate a structured compliance report with:

1. Applicable regulations determination
2. Per-regulation checklist results (PASS / FAIL / PARTIAL / N/A)
3. Gap analysis with specific code references
4. Remediation roadmap prioritized by legal risk
5. Recommended legal consultations (flag items needing lawyer review)

## Supporting Documents

- [patterns.md](patterns.md) — Common compliance anti-patterns
- [reporting.md](reporting.md) — Compliance report template
