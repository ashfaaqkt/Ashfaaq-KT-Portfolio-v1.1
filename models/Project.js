const mongoose = require('mongoose');

const ProjectSchema = new mongoose.Schema({
  title:         { type: String, required: true },
  titleAr:       { type: String, default: '' },
  description:   { type: String, default: '' },
  descriptionAr: { type: String, default: '' },
  github:        { type: String, default: '' },
  demo:          { type: String, default: '' },
  tags:          { type: [String], default: [] },
  badge:         { type: String, default: '' },
  image:         { type: String, default: '' },
  createdAt:     { type: Date, default: Date.now }
});

module.exports = mongoose.model('Project', ProjectSchema);
