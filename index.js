const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const multer = require('multer');
const fs = require('fs');
const FormData = require('form-data');
const path = require('path');
const messages = require('./lang/en.json');
const cors = require('cors');
const ValidationReport = require('./models/ValidationReport'); // Import the model

// Load environment variables securely
require("dotenv").config({ path: "./config.env" });

// MongoDB setup
const mongoose = require('mongoose');

// Read MongoDB URI and database name from environment variables
const mongoURI = process.env.MONGO_URI;
const mongoDB = process.env.MONGO_DB;
const port = process.env.PORT || 3080;
// Load the secret key from environment variables
const HASH_SECRET = process.env.HASH_SECRET || 'default_secret_key';
const CSVLINT_API = process.env.CSVLINT_API;
const HOST = process.env.HOST;

// Connect to MongoDB
mongoose.connect(mongoURI, { dbName: mongoDB });

const db = mongoose.connection;

// Check MongoDB connection
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', function() {
  console.log("Connected to MongoDB database");
});

const app = express();
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 10 * 1024 * 1024 } // Set file size limit to 5MB (adjust as needed)
});
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 5MB limit

function generateTempFileName(prefix, extension) {
  const uniqueId = crypto.randomBytes(8).toString('hex');
  return path.join(__dirname, 'uploads', `${prefix}_${uniqueId}.${extension}`);
}

// Set view engine to EJS
app.set('view engine', 'ejs');

app.use(cors());
app.use(express.static(__dirname + '/public')); // Public directory

app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate'); // HTTP 1.1.
  res.setHeader('Pragma', 'no-cache'); // HTTP 1.0.
  res.setHeader('Expires', '0'); // Proxies.
  next();
});

app.use((req, res, next) => {
  // Read package.json file
  fs.readFile(path.join(__dirname, 'package.json'), 'utf8', (err, data) => {
      if (err) {
          console.error('Error reading package.json:', err);
          return next();
      }

      try {
          const packageJson = JSON.parse(data);
          // Extract version from package.json
          var software = {};
          software.version = packageJson.version;
          software.homepage = packageJson.homepage;
          software.versionLink = packageJson.homepage + "/releases/tag/v" + packageJson.version;
          res.locals.software = software;
      } catch (error) {
          console.error('Error parsing package.json:', error);
      }

      next();
  });
});

// Serve the upload form at "/"
app.get('/', (req, res) => {
  res.render('index');
});

app.get('/api', (req, res) => {
  res.render('api');
});

app.get('/about', (req, res) => {
  res.render('about');
});

app.get('/examples', (req, res) => {
  res.render('examples');
});

app.get('/privacy', (req, res) => {
  res.render('privacy');
});

app.get('/validation/:id', async (req, res) => {
  try {
    const validationReport = await ValidationReport.findById(req.params.id);
    if (!validationReport) {
      return res.status(404).json({ error: 'Validation report not found' });
    }

    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      // Respond with JSON if requested
      res.json(validationReport);
    } else {
      // Render HTML view
      const validationData = validationReport.validation.toObject(); // Convert to plain object
      const data = getHumanReadableMessages(validationData);
      const isEmbedAllowed = false;
      res.render('result', {
        data: data,
        isEmbedAllowed
      });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: 'Error retrieving validation report' });
  }
});

app.get('/validate', async (req, res) => {
  let csvPath, schemaPath;
  try {
    const csvUrl = req.query.csvUrl || '';
    const schemaUrl = req.query.schemaUrl || '';
    const format = req.query.format; // Get the desired format (svg or png)

    // Generate the hash
    const hash = generateHash(csvUrl, schemaUrl);

    const form = new FormData();

    if (csvUrl) {
      const lengthResponse = await axios.head(csvUrl);
      const contentLength = parseInt(lengthResponse.headers['content-length'], 10);

      if (contentLength > MAX_FILE_SIZE) {
        return res.status(400).json({ error: 'CSV file size exceeds the allowed limit' });
      }
      form.append('csvUrl', csvUrl);
    }

    if (schemaUrl) {
      const lengthResponse = await axios.head(schemaUrl);
      const contentLength = parseInt(lengthResponse.headers['content-length'], 10);

      if (contentLength > MAX_FILE_SIZE) {
        return res.status(400).json({ error: 'Schema file size exceeds the allowed limit' });
      }
      form.append('schemaUrl', schemaUrl);
    }

    // Collect dialect options from the query params
    const dialect = {};
    if (req.query.delimiter) dialect.delimiter = req.query.delimiter;
    if (req.query.doubleQuote) dialect.doubleQuote = req.query.doubleQuote === 'true';
    if (req.query.lineTerminator) dialect.lineTerminator = req.query.lineTerminator;
    if (req.query.nullSequence) dialect.nullSequence = req.query.nullSequence;
    if (req.query.quoteChar) dialect.quoteChar = req.query.quoteChar;
    if (req.query.escapeChar) dialect.escapeChar = req.query.escapeChar;
    if (req.query.skipInitialSpace) dialect.skipInitialSpace = req.query.skipInitialSpace === 'true';
    if (req.query.header) dialect.header = req.query.header === 'true';
    if (req.query.caseSensitiveHeader) dialect.caseSensitiveHeader = req.query.caseSensitiveHeader === 'true';

    if (Object.keys(dialect).length > 0) {
      form.append('dialect', JSON.stringify(dialect));
    }

    // Send the form data to the Ruby server
    const response = await axios.post(CSVLINT_API, form, {
      headers: form.getHeaders(),
    });

    // Prepare validation data for storage
    const validationDataForStorage = getValidationDataForStorage(
      response,
      csvUrl,
      schemaUrl
    );
    validationDataForStorage.hash = hash; // Add the hash

    // Use findOneAndUpdate to upsert the validation report and increment validationCount
    const validationReport = await ValidationReport.findOneAndUpdate(
      { hash: hash },
      {
        $set: { ...validationDataForStorage, updatedAt: new Date() },
        $inc: { validationCount: 1 } // Increment validationCount
      },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    // Determine the badge type based on the updated validation result
    let badgeType;
    if (validationReport.validation.errors.length > 0) {
      badgeType = 'invalid';
    } else if (validationReport.validation.warnings.length > 0) {
      badgeType = 'warnings';
    } else {
      badgeType = 'valid';
    }

    // If format is requested as svg or png, respond with the appropriate badge
    if (format === 'svg' || format === 'png') {
      const imagePath = `/images/${badgeType}.${format}`;
      res.sendFile(path.join(__dirname, 'public', imagePath)); // Adjust path if necessary
      return;
    }

    const id = validationReport._id.toString();

    // Prepare the response data
    const JSONResponse = getJSONResponse(response, id, csvUrl, schemaUrl);
    response.data.info = response.data.info_messages;
    delete(response.data.info_messages);
    const humanResponse = getHumanReadableMessages(response.data);
    humanResponse.id = id;

    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      res.json(JSONResponse);
    } else {
      const isEmbedAllowed = true;
      let validationUrl = `${HOST}/validate?csvUrl=${encodeURIComponent(csvUrl)}`;
      if (schemaUrl) {
        validationUrl += `&schemaUrl=${encodeURIComponent(schemaUrl)}`;
      }
      const badgeUrl = `${validationUrl}&format=svg`;
      // Pass this information to the EJS template if embed is allowed
      res.render('result', {
        data: humanResponse,
        isEmbedAllowed,
        validationUrl,
        badgeUrl,
      });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: 'Error validating CSV' });
  } finally {
    if (csvPath) fs.unlinkSync(csvPath);
    if (schemaPath) fs.unlinkSync(schemaPath);
  }
});


// Route to handle CSV file upload and validation
app.post('/validate', (req, res, next) => {
  upload.fields([{ name: 'file' }, { name: 'schema' }])(req, res, (err) => {
    if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File size exceeds the allowed limit of 10mb' });
    } else if (err) {
      return res.status(500).json({ error: 'Error uploading files' });
    }
    next();
  });
}, async (req, res) => {
    let csvPath, schemaPath;
    try {
      const form = new FormData();
      let hash = null;

      // Determine if both inputs are URLs
      const isCsvUrl = Boolean(req.body.csvUrl);
      const isSchemaUrl = Boolean(req.body.schemaUrl);

      if (isCsvUrl) {
        const lengthResponse = await axios.head(req.body.csvUrl);
        const contentLength = parseInt(lengthResponse.headers['content-length'], 10);

        if (contentLength > MAX_FILE_SIZE) {
          return res.status(400).json({ error: 'CSV file size exceeds the allowed limit' });
        }
        form.append('csvUrl', req.body.csvUrl);
      } else if (req.files.file) {
        form.append('file', fs.createReadStream(req.files.file[0].path));
        csvPath = req.files.file[0].path;
      }

      if (isSchemaUrl) {
        const lengthResponse = await axios.head(req.body.schemaUrl);
        const contentLength = parseInt(lengthResponse.headers['content-length'], 10);

        if (contentLength > MAX_FILE_SIZE) {
          return res.status(400).json({ error: 'Schema file size exceeds the allowed limit' });
        }
        form.append('schemaUrl', req.body.schemaUrl);
      } else if (req.files.schema) {
        form.append('schema', fs.createReadStream(req.files.schema[0].path));
        schemaPath = req.files.schema[0].path;
      }

      let isEmbedAllowed = false;

      // Only generate a hash if both inputs are URLs or schema is not provided
      if (isCsvUrl && !req.files.schema) {
        hash = generateHash(req.body.csvUrl, req.body.schemaUrl);
        isEmbedAllowed = true;
      }

      // Collect dialect options from the form data, only if explicitly set
      const dialect = {};
      if (req.body.delimiter) dialect.delimiter = req.body.delimiter;
      if (req.body.doubleQuote) dialect.doubleQuote = req.body.doubleQuote === 'true';
      if (req.body.lineTerminator) dialect.lineTerminator = req.body.lineTerminator;
      if (req.body.nullSequence) dialect.nullSequence = req.body.nullSequence;
      if (req.body.quoteChar) dialect.quoteChar = req.body.quoteChar;
      if (req.body.escapeChar) dialect.escapeChar = req.body.escapeChar;
      if (req.body.skipInitialSpace) dialect.skipInitialSpace = req.body.skipInitialSpace === 'true';
      if (req.body.header) dialect.header = req.body.header === 'true';
      if (req.body.caseSensitiveHeader) dialect.caseSensitiveHeader = req.body.caseSensitiveHeader === 'true';

      // Only send the dialect if it has properties set
      if (Object.keys(dialect).length > 0) {
        form.append('dialect', JSON.stringify(dialect));
      }
      // Send the form data to the Ruby server
      const response = await axios.post(CSVLINT_API, form, {
        headers: form.getHeaders(),
      });

      // Clean up temp files
      if (csvPath) fs.unlinkSync(csvPath);
      if (schemaPath) fs.unlinkSync(schemaPath);

      const validationDataForStorage = getValidationDataForStorage(
        response,
        req.body.csvUrl || csvPath,
        req.body.schemaUrl || schemaPath
      );

      // Set the hash in the validation data if it was generated
      if (hash) {
        validationDataForStorage.hash = hash;
      } else {
        validationDataForStorage.hash = `placeholder_${new mongoose.Types.ObjectId().toHexString()}`;
      }

      // Use findOneAndUpdate if the hash is generated to prevent duplicate entries
      const query = hash ? { hash } : { _id: new mongoose.Types.ObjectId() };
      const updateData = {
        $set: { ...validationDataForStorage, updatedAt: new Date() },
        $inc: { validationCount: 1 } // Increment validationCount
      };

      const validationReport = await ValidationReport.findOneAndUpdate(
        query,
        updateData,
        { new: true, upsert: true, setDefaultsOnInsert: true }
      );

      // Store the validation report in MongoDB
      const id = validationReport._id.toString();

      const JSONResponse = getJSONResponse(
        response,
        id,
        req.body.csvUrl || csvPath,
        req.body.schemaUrl || schemaPath
      );

      response.data.info = response.data.info_messages;
      delete(response.data.info_messages);
      const humanResponse = getHumanReadableMessages(response.data);
      humanResponse.id = id;

      if (req.headers.accept && req.headers.accept.includes('application/json')) {
        // Send JSON response for API
        res.json(JSONResponse);
      } else {
        let validationUrl = `${HOST}/validate?csvUrl=${encodeURIComponent(req.body.csvUrl)}`;
        if (req.body.schemaUrl) {
          validationUrl += `&schemaUrl=${encodeURIComponent(req.body.schemaUrl)}`;
        }
        const badgeUrl = `${validationUrl}&format=svg`;
        // Pass this information to the EJS template if embed is allowed
        res.render('result', {
          data: humanResponse,
          isEmbedAllowed,
          validationUrl,
          badgeUrl,
        });
      }
    } catch (error) {
      console.log(error);
      res.status(500).json({ error: 'Error validating CSV' });
    } finally {
      try {
        fs.unlinkSync(csvPath);
      } catch (unlinkError) {
        //Assume not there
      }

      try {
          fs.unlinkSync(schemaPath);
      } catch (unlinkError) {
        //Assume not there
      }
    }
});

function getValidationDataForStorage(response, csvUrl, schemaUrl) {
    // Ensure warnings and info are arrays of objects, not strings
    const parsedErrors = response.data.errors.map(error => ({
      type: error.type,
      category: error.category || "",
      row: error.row || null,
      column: error.column || null,
    }));

    const parsedWarnings = response.data.warnings.map(warning => ({
      type: warning.type,
      category: warning.category || "",
      row: warning.row || null,
      column: warning.column || null,
    }));

    const parsedInfo = response.data.info_messages.map(info => ({
      type: info.type,
      category: info.category || "",
      row: info.row || null,
      column: info.column || null,
    }));

    // Prepare the validation data for storage
    const validationDataForStorage = {
      version: "0.2",
      licence: "http://opendatacommons.org/licenses/odbl/",
      validation: {
        sourcePresent: Boolean(csvUrl),
        schemaPresent: Boolean(schemaUrl),
        valid: response.data.valid,
        errors: parsedErrors,
        warnings: parsedWarnings,
        info: parsedInfo
      }
    };
    return validationDataForStorage;
}

function getJSONResponse(response, id, csvUrl, schemaUrl) {
  // Format validation data
  const validationData = {
    id: id,
    version: "0.2",
    licence: "http://opendatacommons.org/licenses/odbl/",
    validation: {
      source: csvUrl || "",
      schema: schemaUrl || "",
      valid: response.data.valid,
      errors: response.data.errors.map(error => ({
        type: error.type,
        category: error.category || "",
        row: error.row || null,
        column: error.column || null,
        content: error.content || null,
      })),
      warnings: response.data.warnings.map(warning => ({
        type: warning.type,
        category: warning.category || "",
        row: warning.row || null,
        column: warning.column || null,
        content: warning.content || null,
      })),
      info: response.data.info_messages.map(info => ({
        type: info.type,
        category: info.category || "",
        row: info.row || null,
        column: info.column || null,
        content: info.content || null,
      }))
    }
  };
  return validationData;
}

function getHumanReadableMessages(inputData) {
  // Map error codes to human-readable messages
  const data = {
    ...inputData,
    errors: inputData.errors.map(error => ({
      ...error,
      message: messages.errors[error.type] || error.type
    })),
    warnings: inputData.warnings.map(warning => ({
      ...warning,
      message: messages.warnings[warning.type] || warning.type
    })),
    info: inputData.info.map(info => ({
      ...info,
      message: messages.info[info.type] || info.type
    }))
  };
  return data;
}

function generateHash(csvUrl, schemaUrl) {
  const hmac = crypto.createHmac('sha256', HASH_SECRET);
  hmac.update(csvUrl || '');
  hmac.update(schemaUrl || '');
  return hmac.digest('hex');
}


// Start server
app.listen(port , () => console.log('App listening on port ' + port));