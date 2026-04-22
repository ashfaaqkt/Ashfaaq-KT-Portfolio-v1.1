require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const User = require('./models/User');
const connectDB = require('./lib/db');

const app = express();

// Restrict CORS to the same origin (or a configured allow-list)
const allowedOrigin = process.env.CORS_ORIGIN || null;
app.use(cors(allowedOrigin ? { origin: allowedOrigin } : { origin: false }));

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

// Serve all other static files (HTML, CSS, JS, images, OCC PDFs, etc.)
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

    // Check if user already exists
    let user = await User.findOne({ email });
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
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin Login
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '1d' });
    return res.json({ token });
  } else {
    return res.status(401).json({ message: 'Invalid admin password' });
  }
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
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
}

module.exports = app;
