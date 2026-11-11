const RateLimit = require('../models/RateLimit');

/* ── Client IP (Vercel / proxies put the real client first in x-forwarded-for) ── */
function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length) return fwd.split(',')[0].trim();
  const real = req.headers['x-real-ip'];
  if (typeof real === 'string' && real.length) return real.trim();
  return req.socket?.remoteAddress || 'unknown';
}

/* ── MongoDB-backed fixed-window rate limiter (works on serverless) ── */
async function hitLimit(key, max, windowMs) {
  const now = Date.now();
  const windowStart = Math.floor(now / windowMs) * windowMs;
  const docKey = `${key}:${windowStart}`;
  const doc = await RateLimit.findOneAndUpdate(
    { key: docKey },
    { $inc: { count: 1 }, $setOnInsert: { expiresAt: new Date(windowStart + windowMs) } },
    { upsert: true, new: true }
  );
  return {
    limited: doc.count > max,
    retryAfterSec: Math.ceil((windowStart + windowMs - now) / 1000)
  };
}

/**
 * Express middleware factory.
 *   rateLimit({ name: 'login', max: 10, windowMs: 15 * 60e3 })
 * Keys by client IP. Fails open on DB error so an outage never locks everyone out.
 */
function rateLimit({ name, max, windowMs, message }) {
  return async (req, res, next) => {
    try {
      const { limited, retryAfterSec } = await hitLimit(`${name}:${getClientIp(req)}`, max, windowMs);
      if (limited) {
        res.set('Retry-After', String(retryAfterSec));
        return res.status(429).json({
          code: 'RATE_LIMITED',
          message: message || 'Too many attempts. Please try again later.'
        });
      }
    } catch (err) {
      console.error(`[rateLimit:${name}]`, err.message);
    }
    next();
  };
}

/* ── Input validation ── */
const EMAIL_RE = /^[^\s@<>()[\]\\,;:"]+@[^\s@<>()[\]\\,;:"]+\.[a-z]{2,}$/i;
const NAME_RE = /^[\p{L}\p{M}][\p{L}\p{M}\s.'-]{0,79}$/u;          // letters (any script), spaces, . ' -
const TEXT_RE = /^[^<>{}\\$`]*$/;                                     // free text: no markup / template chars
const PHONE_RE = /^\+\d{1,4}\d{6,14}$/;                               // +<code><number>, digits only
const ALLOWED_CATEGORIES = ['HR', 'Founder', 'Recruiter', 'Viewer'];

function normalizeEmail(email) {
  return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

function cleanText(v) {
  return typeof v === 'string' ? v.trim().replace(/\s+/g, ' ') : '';
}

/** Returns an error message string, or null when the password is acceptable. */
function checkPassword(password, { email, name } = {}) {
  if (typeof password !== 'string') return 'Password is required.';
  if (password.length < 8) return 'Password must be at least 8 characters.';
  if (Buffer.byteLength(password, 'utf8') > 72) return 'Password is too long (max 72 characters).';
  if (!/[A-Za-z]/.test(password) || !/\d/.test(password)) {
    return 'Password must contain at least one letter and one number.';
  }
  const lower = password.toLowerCase();
  const localPart = (email || '').split('@')[0];
  if (localPart.length >= 4 && lower.includes(localPart)) return 'Password must not contain your email.';
  const firstName = (name || '').split(' ')[0].toLowerCase();
  if (firstName.length >= 4 && lower.includes(firstName)) return 'Password must not contain your name.';
  if (/^(.)\1+$/.test(password) || ['password1', '12345678a', 'qwerty123', 'abc12345'].includes(lower)) {
    return 'This password is too common. Please choose another.';
  }
  return null;
}

/** Validates and normalizes the registration payload. Returns { errors, data }. */
function validateRegistration(body = {}) {
  const name = cleanText(body.name);
  const email = normalizeEmail(body.email);
  const phone = typeof body.phone === 'string' ? body.phone.replace(/[\s-]/g, '') : '';
  const company = cleanText(body.company);
  let category = cleanText(body.category);

  if (!name || !NAME_RE.test(name)) return { error: 'Please enter a valid name (letters only, max 80 characters).' };
  if (!email || email.length > 254 || !EMAIL_RE.test(email)) return { error: 'Please enter a valid email address.' };
  if (phone && !PHONE_RE.test(phone)) return { error: 'Please enter a valid phone number.' };
  if (!category) return { error: 'Please select a category.' };
  if (!ALLOWED_CATEGORIES.includes(category)) {
    // "Other" lets the user type their own category
    if (category.length > 50 || !TEXT_RE.test(category)) return { error: 'Please enter a valid category (max 50 characters).' };
  }
  if (company.length > 100 || !TEXT_RE.test(company)) return { error: 'Please enter a valid firm name (max 100 characters).' };

  const pwError = checkPassword(body.password, { email, name });
  if (pwError) return { error: pwError };

  return { data: { name, email, phone, category, company, password: body.password } };
}

module.exports = {
  getClientIp,
  hitLimit,
  rateLimit,
  normalizeEmail,
  validateRegistration,
  checkPassword
};
