require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const User = require('./models/User');
const Timeline = require('./models/Timeline');
const Project = require('./models/Project');
const connectDB = require('./lib/db');
const { rateLimit, normalizeEmail, validateRegistration } = require('./lib/security');
const { getProfileSnapshot } = require('./lib/profile');
const gemini = require('./lib/gemini');
const { generateCv, renderCvPdf, newRef, CvError } = require('./lib/cv');
const { validateCvRequest } = require('./lib/cvRequest');
const { getClientIp, hitLimit } = require('./lib/security');
const { chatReply, validateChatRequest, MAX_MESSAGE: MAX_CHAT_MESSAGE } = require('./lib/chat');
const CvGeneration = require('./models/CvGeneration');

/* ── Multer storage configs ── */
const pdfStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'CV')),
  filename:    (req, file, cb) => cb(null, Date.now() + '-' + path.basename(file.originalname))
});
const imgStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads', 'projects');
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => cb(null, Date.now() + '-' + path.basename(file.originalname))
});
const ppStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'PP')),
  filename:    (req, file, cb) => cb(null, 'pp' + path.extname(file.originalname))
});

const uploadPdf  = multer({ storage: pdfStorage, limits: { fileSize: 20 * 1024 * 1024 }, fileFilter: (r, f, cb) => cb(null, f.mimetype === 'application/pdf') });
const uploadImg  = multer({ storage: imgStorage, limits: { fileSize: 10 * 1024 * 1024 }, fileFilter: (r, f, cb) => cb(null, f.mimetype.startsWith('image/')) });
const uploadPp   = multer({ storage: ppStorage,  limits: { fileSize: 10 * 1024 * 1024 }, fileFilter: (r, f, cb) => cb(null, f.mimetype.startsWith('image/')) });

const app = express();

// Require CORS_ORIGIN in production — open wildcard + credentials is a security risk
const allowedOrigin = process.env.CORS_ORIGIN || null;
if (!allowedOrigin && process.env.NODE_ENV === 'production') {
  console.warn('WARNING: CORS_ORIGIN is not set — all origins are permitted in production.');
}
app.use(cors({
  origin: allowedOrigin
    ? allowedOrigin
    : (origin, cb) => cb(null, true), // allow all in dev; always set CORS_ORIGIN in prod
  credentials: true
}));

app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));

// Basic security headers on every response
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
  });
  next();
});

const PORT = process.env.PORT || 5000;

// Require secrets — refuse to start with known-bad defaults
if (!process.env.JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set.');
  process.exit(1);
}
if (!process.env.ADMIN_PASSWORD) {
  console.error('FATAL: ADMIN_PASSWORD environment variable is not set.');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;
if (JWT_SECRET.length < 32) {
  console.warn('WARNING: JWT_SECRET is shorter than 32 characters — use a long random value.');
}
const JWT_ALGS = { algorithms: ['HS256'] };
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// Database connection middleware (Ensures connection before processing any API route)
app.use(async (req, res, next) => {
  if (req.url.startsWith('/api')) {
    try {
      await connectDB();
      next();
    } catch (err) {
      console.error('Database connection failed:', err);
      return res.status(500).json({ message: 'Database connection failed' });
    }
  } else {
    next();
  }
});

// --- Token verification middleware ---

const verifyToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access denied. Please log in.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET, JWT_ALGS);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Session expired. Please log in again.' });
  }
};

// --- Protected PDF routes (MUST be before express.static) ---

const PROTECTED_FOLDERS = ['BITS', 'CV', 'HSCertificate'];

app.get('/:folder/:filename', (req, res, next) => {
  const { folder } = req.params;
  // Only intercept protected folders; let everything else fall through to static
  if (!PROTECTED_FOLDERS.includes(folder)) return next();

  verifyToken(req, res, () => {
    // Sanitize filename to prevent path traversal
    const safeFilename = path.basename(req.params.filename);
    const folderPath = path.join(__dirname, folder);
    const filePath = path.join(folderPath, safeFilename);

    // Double-check the resolved path stays inside the intended folder
    if (!filePath.startsWith(folderPath + path.sep) && filePath !== folderPath) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    res.sendFile(filePath, (err) => {
      if (err) {
        console.error('File send error:', err);
        res.status(404).json({ message: 'File not found' });
      }
    });
  });
});

// --- Protected OCC sub-folder: Entri & NSDC certificates ---
// Must be before express.static so direct URL access is intercepted first.
app.use((req, res, next) => {
  const decodedPath = decodeURIComponent(req.path);
  // Only protect the Entri & NSDC subfolder inside OCC
  if (!decodedPath.toLowerCase().startsWith('/occ/entri')) return next();

  verifyToken(req, res, () => {
    const relativePath = decodedPath.replace(/^\//, '');
    const safePath = path.normalize(relativePath);

    // Prevent path traversal
    if (safePath.includes('..')) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    const basePath = path.join(__dirname, 'OCC');
    const filePath = path.join(__dirname, safePath);

    // Ensure resolved path stays inside OCC/
    if (!filePath.startsWith(basePath + path.sep)) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    res.sendFile(filePath, (err) => {
      if (err) res.status(404).json({ message: 'File not found' });
    });
  });
});

// Serve uploaded project images
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Middleware to block direct static access to sensitive files and folders
app.use((req, res, next) => {
  const blockedFiles = ['.env', 'package.json', 'package-lock.json', 'server.js', 'vercel.json', '.gitignore'];
  const blockedFolders = ['models', 'lib', 'server', '.git', '.github', '.claude'];
  
  // Normalize the request path to prevent path traversal bypasses
  const normalizedPath = path.normalize(req.path).replace(/^(\.\.(\/|\\|$))+/, '');
  const pathParts = normalizedPath.split(/[/\\]/).filter(Boolean);
  
  if (pathParts.length > 0) {
    const fileName = pathParts[pathParts.length - 1].toLowerCase();
    // Block sensitive files
    if (blockedFiles.includes(fileName)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    // Block sensitive folders
    if (pathParts.some(part => blockedFolders.includes(part.toLowerCase()))) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    // Specifically block static access to files within the api folder (like api/index.js)
    if (pathParts[0].toLowerCase() === 'api' && pathParts.length > 1 && fileName.endsWith('.js')) {
      return res.status(403).json({ message: 'Forbidden' });
    }
  }
  next();
});

// Serve root static files (index.html, styles.css, script.js, etc.)
app.use(express.static(__dirname));

// --- Auth Routes ---

// Auth helpers
const BCRYPT_ROUNDS = 12;
const MAX_FAILED_LOGINS = 5;
const LOCK_MINUTES = 15;
// Compared against when the email doesn't exist, so response time doesn't reveal whether an account exists
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', BCRYPT_ROUNDS);
const CASE_INSENSITIVE = { locale: 'en', strength: 2 };

const signUserToken = (user) =>
  jwt.sign({ id: user._id, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d', algorithm: 'HS256' });

const publicUser = (user) => ({ id: user._id, name: user.name, email: user.email, role: user.role });

// Register — max 5 sign-ups per IP per hour
app.post('/api/auth/register',
  rateLimit({ name: 'register', max: 5, windowMs: 60 * 60 * 1000, message: 'Too many sign-up attempts. Please try again in an hour.' }),
  async (req, res) => {
  try {
    // Honeypot: real users never see or fill this field; bots usually do
    if (req.body && typeof req.body.website === 'string' && req.body.website.trim() !== '') {
      return res.status(400).json({ code: 'INVALID', message: 'Unable to create account.' });
    }

    const { error, data } = validateRegistration(req.body);
    if (error) return res.status(400).json({ code: 'INVALID', message: error });

    const existing = await User.findOne({ email: data.email }).collation(CASE_INSENSITIVE);
    if (existing) {
      return res.status(409).json({ code: 'EMAIL_EXISTS', message: 'An account with this email already exists. Please sign in.' });
    }

    const hashedPassword = await bcrypt.hash(data.password, BCRYPT_ROUNDS);
    const user = new User({
      name: data.name,
      email: data.email,
      phone: data.phone,
      category: data.category,
      company: data.company,
      password: hashedPassword
    });
    await user.save();

    res.json({ token: signUserToken(user), user: publicUser(user) });
  } catch (err) {
    if (err && err.code === 11000) {
      return res.status(409).json({ code: 'EMAIL_EXISTS', message: 'An account with this email already exists. Please sign in.' });
    }
    console.error('[POST /api/auth/register]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login — max 10 attempts per IP per 15 min, plus per-account lockout
app.post('/api/auth/login',
  rateLimit({ name: 'login', max: 10, windowMs: 15 * 60 * 1000, message: 'Too many sign-in attempts. Please try again in 15 minutes.' }),
  async (req, res) => {
  const INVALID = { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' };
  try {
    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;
    if (!email || typeof password !== 'string' || !password || password.length > 200) {
      return res.status(400).json(INVALID);
    }

    const user = await User.findOne({ email }).collation(CASE_INSENSITIVE);
    if (!user) {
      await bcrypt.compare(password, DUMMY_HASH);
      return res.status(400).json(INVALID);
    }

    if (user.lockUntil && user.lockUntil > new Date()) {
      return res.status(429).json({ code: 'ACCOUNT_LOCKED', message: `Too many failed attempts. Please try again in ${LOCK_MINUTES} minutes.` });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      const attempts = (user.failedLoginAttempts || 0) + 1;
      const update = attempts >= MAX_FAILED_LOGINS
        ? { failedLoginAttempts: 0, lockUntil: new Date(Date.now() + LOCK_MINUTES * 60 * 1000) }
        : { failedLoginAttempts: attempts };
      await User.updateOne({ _id: user._id }, { $set: update });
      return res.status(400).json(INVALID);
    }

    if (user.failedLoginAttempts || user.lockUntil) {
      await User.updateOne({ _id: user._id }, { $set: { failedLoginAttempts: 0, lockUntil: null } });
    }

    res.json({ token: signUserToken(user), user: publicUser(user) });
  } catch (err) {
    console.error('[POST /api/auth/login]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin Login
app.post('/api/admin/login',
  rateLimit({ name: 'admin-login', max: 5, windowMs: 15 * 60 * 1000, message: 'Too many attempts. Please try again in 15 minutes.' }),
  (req, res) => {
  const { password } = req.body;
  if (typeof password !== 'string' || !password) {
    return res.status(401).json({ message: 'Invalid admin password' });
  }
  // Timing-safe comparison using SHA-256 hashes to prevent length leaks and side-channel timing attacks
  const hashedInput = crypto.createHash('sha256').update(password).digest();
  const hashedSecret = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest();
  const match = crypto.timingSafeEqual(hashedInput, hashedSecret);
  if (match) {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '1d', algorithm: 'HS256' });
    return res.json({ token });
  }
  return res.status(401).json({ message: 'Invalid admin password' });
});

// --- Admin Routes ---

// Middleware to check admin token
const verifyAdmin = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET, JWT_ALGS);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized as admin' });
    }
    next();
  } catch (err) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};

// Get all users
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password -failedLoginAttempts -lockUntil').sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    console.error('[GET /api/admin/users]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete a user
app.delete('/api/admin/users/:id', verifyAdmin, async (req, res) => {
  try {
    const deleted = await User.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'User deleted' });
  } catch (err) {
    console.error('[DELETE /api/admin/users/:id]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ─── AI Routes (admin) ──────────────────────────────────────────────────────

// Status: is Gemini configured, which models are pinned (never exposes the key)
app.get('/api/admin/ai/status', verifyAdmin, (req, res) => {
  let snapshotOk = true, snapshotError = null;
  try { getProfileSnapshot(); } catch (err) { snapshotOk = false; snapshotError = err.message; }
  res.json({ geminiConfigured: gemini.isConfigured(), models: gemini.MODELS, snapshotOk, snapshotError });
});

// The exact profile data the AI features are allowed to use — for review
app.get('/api/admin/ai/profile-snapshot', verifyAdmin, (req, res) => {
  try {
    res.json(getProfileSnapshot({ fresh: req.query.fresh === '1' }));
  } catch (err) {
    console.error('[GET /api/admin/ai/profile-snapshot]', err.message);
    res.status(500).json({ message: 'Could not build profile snapshot' });
  }
});

// ─── "Ask Ashfaaq" chatbot (public, no sign-in) ─────────────────────────────

const CHAT_DAILY_CAP = Math.max(1, Number(process.env.CHAT_DAILY_CAP) || 1500);   // site-wide safety cap
const chatEnabled = () => process.env.CHAT_ENABLED !== 'false' && gemini.isConfigured();

app.get('/api/chat/status', (req, res) => {
  res.json({ enabled: chatEnabled(), maxMessage: MAX_CHAT_MESSAGE });
});

app.post('/api/chat',
  rateLimit({ name: 'chat-burst', max: 15, windowMs: 5 * 60e3, message: 'You are sending messages too quickly. Please wait a few minutes.' }),
  rateLimit({ name: 'chat-day', max: 120, windowMs: 24 * 60 * 60e3, message: 'Daily message limit reached. Please try again tomorrow.' }),
  async (req, res) => {
    if (!chatEnabled()) return res.status(503).json({ code: 'OFF', message: 'The assistant is unavailable right now.' });
    const v = validateChatRequest(req.body);
    if (v.error) return res.status(400).json({ code: v.error, message: 'Invalid message.' });
    try {
      const { limited } = await hitLimit('chat-global', CHAT_DAILY_CAP, 24 * 60 * 60e3);
      if (limited) return res.status(503).json({ code: 'BUSY', message: 'The assistant is busy today. Please try again later.' });
    } catch (err) { console.error('[chat cap]', err.message); }
    try {
      const reply = await chatReply(v);
      res.json({ reply });
    } catch (err) {
      const code = err instanceof gemini.GeminiError ? err.code : 'SERVER';
      if (!(err instanceof gemini.GeminiError)) console.error('[POST /api/chat]', err.message);
      const status = code === 'RATE_LIMITED' ? 429 : code === 'BLOCKED' ? 422 : 502;
      res.status(status).json({ code, message: 'The assistant could not answer. Please try again.' });
    }
  });

// ─── Tailored CV Generator ──────────────────────────────────────────────────

const CV_MONTHLY_LIMIT = 3;
const CV_DAILY_CAP = Math.max(1, Number(process.env.CV_DAILY_CAP) || 60);   // site-wide safety cap
const cvEnabled = () => process.env.CV_GENERATOR_ENABLED !== 'false' && gemini.isConfigured();

const monthStartUtc = (d = new Date()) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1));
const nextMonthUtc = (d = new Date()) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1));
const dayStartUtc = (d = new Date()) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));

const COUNTED = { status: { $in: ['pending', 'ready', 'downloaded'] }, countsTowardQuota: { $ne: false } };

async function cvQuota(userId) {
  const used = await CvGeneration.countDocuments({ user: userId, createdAt: { $gte: monthStartUtc() }, ...COUNTED });
  return { used, limit: CV_MONTHLY_LIMIT, remaining: Math.max(0, CV_MONTHLY_LIMIT - used), resetsAt: nextMonthUtc().toISOString() };
}

const isObjectId = (v) => typeof v === 'string' && /^[a-f0-9]{24}$/i.test(v);

// Quota + availability for the signed-in user
app.get('/api/cv/quota', verifyToken, async (req, res) => {
  try {
    if (!isObjectId(req.user?.id)) return res.status(401).json({ code: 'AUTH', message: 'Please sign in.' });
    res.json({ enabled: cvEnabled(), ...(await cvQuota(req.user.id)) });
  } catch (err) {
    console.error('[GET /api/cv/quota]', err.message);
    res.status(500).json({ code: 'SERVER', message: 'Server error' });
  }
});

// Generate a tailored CV → returns the PDF (base64) for preview + download
app.post('/api/cv/generate',
  verifyToken,
  rateLimit({ name: 'cv-generate', max: 8, windowMs: 60 * 60 * 1000, message: 'Too many requests. Please try again later.' }),
  async (req, res) => {
  const started = Date.now();
  let record = null;
  try {
    if (!cvEnabled()) return res.status(503).json({ code: 'DISABLED', message: 'The CV generator is temporarily unavailable.' });
    if (!isObjectId(req.user?.id)) return res.status(401).json({ code: 'AUTH', message: 'Please sign in.' });

    const { error, job } = validateCvRequest(req.body);
    if (error) return res.status(400).json({ code: error, message: 'Please check the form and try again.' });

    const user = await User.findById(req.user.id).select('name email');
    if (!user) return res.status(401).json({ code: 'AUTH', message: 'Please sign in again.' });

    // One generation at a time per user
    const busy = await CvGeneration.exists({ user: user._id, status: 'pending', createdAt: { $gte: new Date(Date.now() - 3 * 60 * 1000) } });
    if (busy) return res.status(409).json({ code: 'BUSY', message: 'A CV is already being generated. Please wait.' });

    // Site-wide daily cap (protects the API budget)
    const today = await CvGeneration.countDocuments({ createdAt: { $gte: dayStartUtc() }, status: { $ne: 'failed' } });
    if (today >= CV_DAILY_CAP) return res.status(503).json({ code: 'DAILY_CAP', message: 'Daily limit reached for the CV generator. Please try again tomorrow.' });

    // Reserve a slot first, then count (so parallel requests can't exceed the quota)
    record = await CvGeneration.create({
      ref: newRef(), user: user._id, userName: user.name, userEmail: user.email, job, ip: getClientIp(req), model: gemini.MODELS.cv
    });
    const quota = await cvQuota(user._id);
    if (quota.used > CV_MONTHLY_LIMIT) {
      await CvGeneration.deleteOne({ _id: record._id });
      record = null;
      const q = await cvQuota(user._id);
      return res.status(429).json({ code: 'QUOTA', message: 'You have used all CV generations for this month.', quota: q });
    }

    const out = await generateCv(job, { ref: record.ref });
    await CvGeneration.updateOne({ _id: record._id }, { $set: {
      status: 'ready', cv: out.cv, meta: out.meta, match: out.cv.match, validator: out.cv.report,
      pages: out.pages, fileName: out.fileName, durationMs: Date.now() - started
    } });

    res.json({
      ref: record.ref,
      fileName: out.fileName,
      pages: out.pages,
      requestedPages: job.pages,
      language: job.language,
      match: out.cv.match,
      pdfBase64: out.pdf.toString('base64'),
      quota: await cvQuota(user._id)
    });
  } catch (err) {
    const code = err instanceof gemini.GeminiError ? `AI_${err.code}` : (err instanceof CvError ? err.code : 'SERVER');
    console.error('[POST /api/cv/generate]', code, err instanceof gemini.GeminiError || err instanceof CvError ? '' : err.message);
    if (record) {
      // Failed generations never count toward the quota
      await CvGeneration.updateOne({ _id: record._id }, { $set: { status: 'failed', failure: code, durationMs: Date.now() - started } }).catch(() => {});
    }
    const status = code === 'AI_RATE_LIMITED' ? 503 : code === 'AI_TIMEOUT' ? 504 : 500;
    res.status(status).json({ code, message: 'We could not generate the CV right now. This attempt was not counted. Please try again.' });
  }
});

// Mark a generation as downloaded (for the admin list)
app.post('/api/cv/:ref/downloaded', verifyToken, async (req, res) => {
  try {
    if (!isObjectId(req.user?.id) || !/^CV-[A-Z0-9]{8}$/.test(req.params.ref)) return res.status(400).json({ code: 'INVALID' });
    await CvGeneration.updateOne({ ref: req.params.ref, user: req.user.id, status: { $in: ['ready', 'downloaded'] } },
      { $set: { status: 'downloaded', downloadedAt: new Date() } });
    res.json({ ok: true });
  } catch (err) {
    console.error('[POST /api/cv/:ref/downloaded]', err.message);
    res.status(500).json({ code: 'SERVER' });
  }
});

// ── Admin: CV generations ──
app.get('/api/admin/cv-generations', verifyAdmin, async (req, res) => {
  try {
    const items = await CvGeneration.find()
      .select('ref userName userEmail status failure job.jobTitle job.company job.language job.pages job.seniority job.workMode job.mustHaveSkills match pages durationMs countsTowardQuota downloadedAt createdAt')
      .sort({ createdAt: -1 }).limit(500).lean();
    res.json(items);
  } catch (err) {
    console.error('[GET /api/admin/cv-generations]', err.message);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/admin/cv-generations/:ref', verifyAdmin, async (req, res) => {
  try {
    const item = await CvGeneration.findOne({ ref: String(req.params.ref) }).lean();
    if (!item) return res.status(404).json({ message: 'Not found' });
    res.json(item);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Re-download: re-renders the stored CV deterministically (no AI call, no quota)
app.get('/api/admin/cv-generations/:ref/pdf', verifyAdmin, async (req, res) => {
  try {
    const item = await CvGeneration.findOne({ ref: String(req.params.ref), status: { $in: ['ready', 'downloaded'] } }).lean();
    if (!item || !item.cv) return res.status(404).json({ message: 'Not found' });
    const { buffer } = await renderCvPdf(item.cv, item.meta, item.job.pages);
    res.set({ 'Content-Type': 'application/pdf', 'Content-Disposition': `attachment; filename="${item.fileName || item.ref + '.pdf'}"`, 'Cache-Control': 'no-store' });
    res.send(buffer);
  } catch (err) {
    console.error('[GET /api/admin/cv-generations/:ref/pdf]', err.message);
    res.status(500).json({ message: 'Could not render PDF' });
  }
});

app.delete('/api/admin/cv-generations/:ref', verifyAdmin, async (req, res) => {
  try {
    const r = await CvGeneration.deleteOne({ ref: String(req.params.ref) });
    if (!r.deletedCount) return res.status(404).json({ message: 'Not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Reset a user's quota for the current month (their past CVs stay in the list)
app.post('/api/admin/cv-quota/:userId/reset', verifyAdmin, async (req, res) => {
  try {
    if (!isObjectId(req.params.userId)) return res.status(400).json({ message: 'Invalid user' });
    const r = await CvGeneration.updateMany({ user: req.params.userId, createdAt: { $gte: monthStartUtc() } }, { $set: { countsTowardQuota: false } });
    res.json({ message: 'Quota reset', updated: r.modifiedCount });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ─── Timeline Routes ────────────────────────────────────────────────────────

// Public — read all (used by main site too)
app.get('/api/timeline', async (req, res) => {
  try {
    const items = await Timeline.find().sort({ createdAt: -1 });
    res.json(items);
  } catch (err) {
    console.error('[GET /api/timeline]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/admin/timeline', verifyAdmin, async (req, res) => {
  try {
    const { title, titleAr, company, period, type, description, descriptionAr, pdfPath } = req.body;
    if (!title) return res.status(400).json({ message: 'Title is required' });
    const item = new Timeline({ title, titleAr, company, period, type, description, descriptionAr, pdfPath });
    await item.save();
    res.status(201).json(item);
  } catch (err) {
    console.error('[POST /api/admin/timeline]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/admin/timeline/:id', verifyAdmin, async (req, res) => {
  try {
    const { title, titleAr, company, period, type, description, descriptionAr, pdfPath } = req.body;
    const update = { title, titleAr, company, period, type, description, descriptionAr };
    if (pdfPath) update.pdfPath = pdfPath;
    const item = await Timeline.findByIdAndUpdate(req.params.id, update, { new: true, runValidators: true });
    if (!item) return res.status(404).json({ message: 'Entry not found' });
    res.json(item);
  } catch (err) {
    console.error('[PUT /api/admin/timeline/:id]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/admin/timeline/:id', verifyAdmin, async (req, res) => {
  try {
    const item = await Timeline.findByIdAndDelete(req.params.id);
    if (!item) return res.status(404).json({ message: 'Entry not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('[DELETE /api/admin/timeline/:id]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// PDF upload (saves to /CV/)
app.post('/api/admin/upload-pdf', verifyAdmin, uploadPdf.single('pdf'), (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No PDF uploaded' });
  res.json({ path: '/CV/' + req.file.filename });
});

// ─── Project Routes ──────────────────────────────────────────────────────────

// Public — read all
app.get('/api/projects', async (req, res) => {
  try {
    const items = await Project.find().sort({ createdAt: -1 });
    res.json(items);
  } catch (err) {
    console.error('[GET /api/projects]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/admin/projects', verifyAdmin, uploadImg.single('image'), async (req, res) => {
  try {
    const tags = req.body.tags ? req.body.tags.split(',').map(t => t.trim()).filter(Boolean) : [];
    const project = new Project({
      title:         req.body.title,
      titleAr:       req.body.titleAr || '',
      description:   req.body.description || '',
      descriptionAr: req.body.descriptionAr || '',
      github:        req.body.github || '',
      demo:          req.body.demo || '',
      tags,
      badge:         req.body.badge || '',
      image:         req.file ? '/uploads/projects/' + req.file.filename : ''
    });
    await project.save();
    res.status(201).json(project);
  } catch (err) {
    console.error('[POST /api/admin/projects]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/admin/projects/:id', verifyAdmin, uploadImg.single('image'), async (req, res) => {
  try {
    const tags = req.body.tags ? req.body.tags.split(',').map(t => t.trim()).filter(Boolean) : [];
    const update = {
      title:         req.body.title,
      titleAr:       req.body.titleAr || '',
      description:   req.body.description || '',
      descriptionAr: req.body.descriptionAr || '',
      github:        req.body.github || '',
      demo:          req.body.demo || '',
      tags,
      badge:         req.body.badge || ''
    };
    if (req.file) update.image = '/uploads/projects/' + req.file.filename;

    const project = await Project.findByIdAndUpdate(req.params.id, update, { new: true, runValidators: true });
    if (!project) return res.status(404).json({ message: 'Project not found' });
    res.json(project);
  } catch (err) {
    console.error('[PUT /api/admin/projects/:id]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/admin/projects/:id', verifyAdmin, async (req, res) => {
  try {
    const project = await Project.findByIdAndDelete(req.params.id);
    if (!project) return res.status(404).json({ message: 'Project not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('[DELETE /api/admin/projects/:id]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ─── Settings — Profile Picture ───────────────────────────────────────────────

app.post('/api/admin/profile-picture', verifyAdmin, uploadPp.single('photo'), (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No image uploaded' });
  res.json({ path: '/PP/' + req.file.filename });
});

// ─────────────────────────────────────────────────────────────────────────────

if (require.main === module) {
  app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
}

module.exports = app;
