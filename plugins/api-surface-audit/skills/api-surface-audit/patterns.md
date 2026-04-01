# Common API Security Anti-Patterns

## Pattern 1: Unauthenticated Data Endpoint

```typescript
// VULNERABLE: No auth on endpoint returning student data
router.get("/api/classes/:classId/students", async (req, res) => {
  const students = await Student.findAll({ where: { classId: req.params.classId } });
  res.json(students);
});

// FIXED: Auth + authorization + tenant scoping
router.get("/api/classes/:classId/students",
  authMiddleware,
  requireRole(["teacher", "admin"]),
  async (req, res) => {
    const students = await Student.findAll({
      where: { classId: req.params.classId, orgId: req.user.orgId },
      attributes: ["id", "displayName", "avatarUrl"], // Minimal fields
    });
    res.json(students);
  }
);
```

## Pattern 2: No Input Validation

```typescript
// VULNERABLE: Raw user input used in query
router.get("/api/search", async (req, res) => {
  const results = await db.query(`SELECT * FROM students WHERE name LIKE '%${req.query.q}%'`);
  res.json(results);
});

// FIXED: Validated, parameterized, paginated
router.get("/api/search",
  authMiddleware,
  validate(z.object({ q: z.string().min(2).max(100), page: z.number().int().min(1).default(1) })),
  async (req, res) => {
    const results = await Student.findAll({
      where: { name: { [Op.iLike]: `%${req.query.q}%` }, orgId: req.user.orgId },
      limit: 20,
      offset: (req.query.page - 1) * 20,
      attributes: ["id", "displayName"],
    });
    res.json(results);
  }
);
```

## Pattern 3: Verbose Error Responses

```typescript
// VULNERABLE: Leaks internal details
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    query: err.sql, // Leaks SQL query structure
    connectionString: err.connectionString, // Leaks DB connection
  });
});

// FIXED: Generic errors in production
app.use((err, req, res, next) => {
  const requestId = crypto.randomUUID();
  logger.error(`[${requestId}] ${err.message}`, { stack: err.stack, path: req.path });

  if (process.env.NODE_ENV === "production") {
    res.status(500).json({ error: "Internal server error", requestId });
  } else {
    res.status(500).json({ error: err.message, requestId });
  }
});
```

## Pattern 4: Overly Permissive CORS

```typescript
// VULNERABLE: Any origin can make requests
app.use(cors({ origin: "*", credentials: true }));

// FIXED: Explicit origin whitelist
app.use(cors({
  origin: ["https://teacher.madlen.io", "https://student.madlen.io"],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
```

## Pattern 5: No Pagination on List Endpoints

```typescript
// VULNERABLE: Returns entire dataset
router.get("/api/students", async (req, res) => {
  const students = await Student.findAll(); // Could be millions of records
  res.json(students);
});

// FIXED: Required pagination with max limit
router.get("/api/students",
  authMiddleware,
  validate(z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
  })),
  async (req, res) => {
    const { page, limit } = req.query;
    const { rows, count } = await Student.findAndCountAll({
      where: { orgId: req.user.orgId },
      limit,
      offset: (page - 1) * limit,
    });
    res.json({ data: rows, total: count, page, totalPages: Math.ceil(count / limit) });
  }
);
```

## Pattern 6: GraphQL Introspection in Production

```typescript
// VULNERABLE: Schema fully visible in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true, // Attackers can map your entire API
});

// FIXED: Disable in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== "production",
  plugins: [
    process.env.NODE_ENV === "production" && ApolloServerPluginLandingPageDisabled(),
  ].filter(Boolean),
});
```

## Pattern 7: Missing Security Headers

```typescript
// VULNERABLE: No security headers set
app.listen(3000);

// FIXED: Comprehensive security headers via Helmet
import helmet from "helmet";
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
}));
```

## Pattern 8: File Upload Without Restrictions

```typescript
// VULNERABLE: Any file type, any size
const upload = multer({ dest: "uploads/" });
router.post("/api/upload", upload.single("file"), async (req, res) => {
  res.json({ url: `/uploads/${req.file.filename}` });
});

// FIXED: Type whitelist, size limit, secure storage
const upload = multer({
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB max
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "image/gif", "application/pdf"];
    cb(null, allowed.includes(file.mimetype));
  },
  storage: multer.memoryStorage(), // Don't write to disk directly
});

router.post("/api/upload", authMiddleware, upload.single("file"), async (req, res) => {
  const safeFilename = `${req.user.orgId}/${crypto.randomUUID()}${path.extname(req.file.originalname)}`;
  await s3.upload({ Key: safeFilename, Body: req.file.buffer, ContentType: req.file.mimetype });
  res.json({ url: getSignedUrl(safeFilename) }); // Signed URL, not direct path
});
```
