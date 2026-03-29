require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const connectDB = require('./lib/db');

const app = express();
app.use(cors());
app.use(express.json());

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
const path = require('path');

// Serve static files from the current directory (the portfolio root)
app.use(express.static(__dirname));

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';


// Connect to MongoDB (initial connection for non-API routes if needed)
// Inline mongoose.connect removed in favor of connectDB middleware

// --- Auth Routes ---

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, category, company, password } = req.body;
    
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
    // Return an admin token
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
