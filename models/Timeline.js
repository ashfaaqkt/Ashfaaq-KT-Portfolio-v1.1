const mongoose = require('mongoose');

const TimelineSchema = new mongoose.Schema({
  title:         { type: String, required: true },
  titleAr:       { type: String, default: '' },
  company:       { type: String, default: '' },
  period:        { type: String, default: '' },
  type:          { type: String, enum: ['experience', 'education'], default: 'experience' },
  description:   { type: String, default: '' },
  descriptionAr: { type: String, default: '' },
  pdfPath:       { type: String, default: '' },
  createdAt:     { type: Date, default: Date.now }
});

module.exports = mongoose.model('Timeline', TimelineSchema);
