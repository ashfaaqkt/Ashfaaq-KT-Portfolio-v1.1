const mongoose = require('mongoose');

// Fixed-window counters shared across all serverless instances.
// Documents delete themselves after `expiresAt` (MongoDB TTL index).
const RateLimitSchema = new mongoose.Schema({
  key:       { type: String, required: true, unique: true },
  count:     { type: Number, default: 0 },
  expiresAt: { type: Date, required: true }
});

RateLimitSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('RateLimit', RateLimitSchema);
