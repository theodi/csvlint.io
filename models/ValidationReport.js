const mongoose = require('mongoose');

const validationEntrySchema = new mongoose.Schema(
  {
    type: { type: String },
    category: { type: String },
    row: { type: Number, default: null },
    column: { type: Number, default: null }
  },
  { _id: false } // Prevent _id generation for each entry
);

const validationReportSchema = new mongoose.Schema(
  {
    version: { type: String },
    licence: { type: String },
    hash: { type: String, unique: true },
    sourceDomain: { type: String },
    schemaDomain: { type: String },
    validationCount: { type: Number, default: 1 }, // Initialize validationCount
    validation: {
      sourcePresent: { type: Boolean },
      schemaPresent: { type: Boolean },
      type: { type: String },
      valid: { type: Boolean },
      errors: [validationEntrySchema],
      warnings: [validationEntrySchema],
      info: [validationEntrySchema]
    }
  },
  {
    timestamps: { createdAt: 'createdAt', updatedAt: 'lastModified' }
  }
);

module.exports = mongoose.model('ValidationReport', validationReportSchema);