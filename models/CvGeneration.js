const mongoose = require('mongoose');

// One document per CV generation. Auto-deleted 12 months after creation
// (MongoDB TTL index) — matches the privacy policy.
const RETENTION_SECONDS = 365 * 24 * 60 * 60;

const CvGenerationSchema = new mongoose.Schema({
  ref:        { type: String, required: true, unique: true },   // e.g. CV-7KX2M9QA (printed on the PDF)
  user:       { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  userName:   { type: String, default: '' },                     // kept for the admin list if the user is deleted
  userEmail:  { type: String, default: '' },
  status:     { type: String, enum: ['pending', 'ready', 'downloaded', 'failed'], default: 'pending', index: true },
  countsTowardQuota: { type: Boolean, default: true },          // admin "reset quota" sets this to false
  failure:    { type: String, default: '' },                     // safe error code only
  // Recruiter's request
  job: {
    jobTitle:       String,
    company:        String,
    jobDescription: String,
    mustHaveSkills: [String],
    seniority:      String,
    workMode:       String,
    language:       { type: String, enum: ['en', 'ar'] },
    pages:          { type: Number, enum: [1, 2] }
  },
  // Result (JSON, not the PDF — the PDF is re-rendered deterministically on demand)
  cv:         { type: mongoose.Schema.Types.Mixed, default: null },
  meta:       { type: mongoose.Schema.Types.Mixed, default: null },
  match:      { matched: [String], missing: [String] },
  validator:  { type: mongoose.Schema.Types.Mixed, default: null }, // what the validator rejected (audit trail)
  pages:      { type: Number, default: 0 },
  fileName:   { type: String, default: '' },
  model:      { type: String, default: '' },
  durationMs: { type: Number, default: 0 },
  ip:         { type: String, default: '' },
  downloadedAt: { type: Date, default: null },
  createdAt:  { type: Date, default: Date.now }
});

CvGenerationSchema.index({ createdAt: 1 }, { expireAfterSeconds: RETENTION_SECONDS });
CvGenerationSchema.index({ user: 1, createdAt: -1 });

module.exports = mongoose.model('CvGeneration', CvGenerationSchema);
