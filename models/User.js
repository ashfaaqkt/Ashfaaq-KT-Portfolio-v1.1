const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true, maxlength: 80 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254, match: [/^\S+@\S+\.\S+$/, 'Invalid email format'] },
  phone: { type: String, default: '', maxlength: 20 },
  category: { type: String, required: true, maxlength: 50 },
  company: { type: String, default: '', maxlength: 100 },
  password: { type: String, required: true },
  role: { type: String, default: 'user' }, // 'user' or 'admin'
  // Account lockout after repeated failed logins
  failedLoginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', UserSchema);
