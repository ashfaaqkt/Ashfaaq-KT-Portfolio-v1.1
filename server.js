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

app.use(express.json());

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
    const decoded = jwt.verify(token, JWT_SECRET);
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

// Serve uploaded project images
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Middleware to block direct static access to sensitive files and folders
app.use((req, res, next) => {
  const blockedFiles = ['.env', 'package.json', 'package-lock.json', 'server.js', 'vercel.json', '.gitignore'];
  const blockedFolders = ['models', 'lib', 'api', 'server', '.git', '.github', '.claude'];
  
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
  }
  next();
});

// Serve root static files (index.html, styles.css, script.js, etc.)
app.use(express.static(__dirname));

// --- Auth Routes ---

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, category, company, password } = req.body;

    if (!name || !email || !password || !category) {
      return res.status(400).json({ message: 'Name, email, category, and password are required.' });
    }
    if (typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters.' });
    }

    // Check if user already exists — cast to string to prevent NoSQL injection
    let user = await User.findOne({ email: String(email) });
    if (user) return res.status(400).json({ message: 'User already exists' });

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({
      name, email, phone, category, company, password: hashedPassword
    });

    await user.save();

    // Create JWT
    const token = jwt.sign({ id: user._id, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });

  } catch (err) {
    console.error('[POST /api/auth/register]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email: String(email) });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });

  } catch (err) {
    console.error('[POST /api/auth/login]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin Login
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (typeof password !== 'string' || !password) {
    return res.status(401).json({ message: 'Invalid admin password' });
  }
  // Timing-safe comparison using SHA-256 hashes to prevent length leaks and side-channel timing attacks
  const hashedInput = crypto.createHash('sha256').update(password).digest();
  const hashedSecret = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest();
  const match = crypto.timingSafeEqual(hashedInput, hashedSecret);
  if (match) {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '1d' });
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
    const decoded = jwt.verify(token, JWT_SECRET);
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
    const users = await User.find().select('-password').sort({ createdAt: -1 });
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

if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
}

module.exports = app;
