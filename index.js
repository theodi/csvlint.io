const express = require('express');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const axios = require('axios');
const multer = require('multer');
const fs = require('fs');
const FormData = require('form-data');
const path = require('path');
const messages = require('./lang/en.json');
const cors = require('cors');
const helmet = require('helmet');
const validator = require('validator');
const ValidationReport = require('./models/ValidationReport'); // Import the model
const { URL } = require('url');

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

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"], // Only allow scripts from same origin
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// File type validation function
function validateFileType(file, allowedTypes) {
  if (!file) return false;
  
  const allowedMimeTypes = {
    'csv': ['text/csv', 'application/csv', 'text/plain', 'application/vnd.ms-excel'],
    'json': ['application/json', 'text/json']
  };
  
  const fileExtension = path.extname(file.originalname).toLowerCase().substring(1);
  const mimeType = file.mimetype;
  
  /*
  console.log('File validation debug:');
  console.log('File:', file.originalname);
  console.log('Extension:', fileExtension);
  console.log('MIME type:', mimeType);
  console.log('Allowed types:', allowedTypes);
  console.log('Allowed MIME types for extension:', allowedMimeTypes[fileExtension]);
  */
  if (!allowedTypes.includes(fileExtension)) {
    //console.log('Rejected: Extension not in allowed types');
    return false;
  }
  
  if (!allowedMimeTypes[fileExtension] || !allowedMimeTypes[fileExtension].includes(mimeType)) {
    //console.log('Rejected: MIME type not allowed for this extension');
    return false;
  }
  
  //console.log('File validation passed');
  return true;
}

// URL validation function
function validateUrl(url) {
  if (!url) return false;
  
  // Decode HTML entities in the URL (safety measure)
  const decodedUrl = url.replace(/&#x2F;/g, '/').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
  
  try {
    const parsedUrl = new URL(decodedUrl);
    
    // Block dangerous protocols
    if (['file:', 'data:', 'javascript:', 'vbscript:'].includes(parsedUrl.protocol)) {
      return false;
    }
    
    // Allow localhost URLs if they point to our own server
    const hostname = parsedUrl.hostname;
    const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
    
    if (isLocalhost) {
      // Check if the localhost URL points to our own server
      const serverHost = process.env.HOST || 'localhost';
      const serverPort = process.env.PORT || '3080';
      const serverUrl = `http://${serverHost}:${serverPort}`;
      
      // Allow if it's our own server
      if (decodedUrl.startsWith(serverUrl) || decodedUrl.startsWith(`http://localhost:${serverPort}`) || decodedUrl.startsWith(`http://127.0.0.1:${serverPort}`)) {
        // For localhost URLs pointing to our server, use basic URL validation instead of validator.isURL
        return parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:';
      }
      
      // Block other localhost URLs
      return false;
    }
    
    // Block private IP ranges
    const privateIPRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./
    ];
    
    if (privateIPRanges.some(range => range.test(hostname))) {
      return false;
    }
    
    // For external URLs, use the validator library
    return validator.isURL(decodedUrl, { protocols: ['http', 'https'] });
  } catch (error) {
    return false;
  }
}

// Function to validate that a URL points to a CSV file
async function validateCsvUrl(url) {
  try {
    // First check the file extension
    const urlPath = new URL(url).pathname.toLowerCase();
    const allowedExtensions = ['.csv', '.tsv', '.txt'];
    const hasValidExtension = allowedExtensions.some(ext => urlPath.endsWith(ext));
    
    if (!hasValidExtension) {
      return { isValid: false, reason: 'URL does not have a valid CSV file extension (.csv, .tsv, .txt)' };
    }
    
    // Then check the content type with a HEAD request
    const response = await axios.head(url, {
      timeout: 5000, // 5 second timeout for content type check
      maxRedirects: 3
    });
    
    const contentType = response.headers['content-type']?.toLowerCase() || '';
    
    // Check for CSV content types
    const csvContentTypes = [
      'text/csv',
      'application/csv',
      'text/tab-separated-values',
      'text/plain'
    ];
    
    const hasValidContentType = csvContentTypes.some(type => contentType.includes(type));
    
    if (!hasValidContentType) {
      return { 
        isValid: false, 
        reason: `URL content type '${contentType}' is not a valid CSV type. Expected: text/csv, application/csv, text/tab-separated-values, or text/plain` 
      };
    }
    
    return { isValid: true };
  } catch (error) {
    return { 
      isValid: false, 
      reason: `Failed to validate URL: ${error.message}` 
    };
  }
}

// Input sanitization function
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return validator.escape(input.trim());
}

const upload = multer({
  dest: 'uploads/',
  limits: { 
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 2 // Maximum 2 files (CSV + schema)
  },
  fileFilter: (req, file, cb) => {
    // Validate file type based on field name
    if (file.fieldname === 'file') {
      if (!validateFileType(file, ['csv'])) {
        return cb(new Error('Invalid CSV file type'), false);
      }
    } else if (file.fieldname === 'schema') {
      if (!validateFileType(file, ['json'])) {
        return cb(new Error('Invalid JSON schema file type'), false);
      }
    }
    cb(null, true);
  }
});
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB limit

function generateTempFileName(prefix, extension) {
  const uniqueId = crypto.randomBytes(8).toString('hex');
  return path.join(__dirname, 'uploads', `${prefix}_${uniqueId}.${extension}`);
}

// Define rate limiting settings
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
  message: { error: "Too many requests from this IP, please try again after 15 minutes." },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  // Trust proxy to get real IP address
  trustProxy: true,
  handler: (req, res, next, options) => {
    // Debug output when the limit is exceeded
    if (req.rateLimit.remaining === 0) {
      console.log(`Rate limit exceeded: IP ${req.ip} - Time: ${new Date().toISOString()}`);
    }

    // Send the rate-limit message
    res.status(options.statusCode).send(options.message);
  }
});

// Middleware to conditionally apply rate limiting
const conditionalRateLimit = (req, res, next) => {
  const csvUrl = req.query.csvUrl || '';
  
  // Get the real IP address, considering forwarded headers
  const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                   req.headers['x-real-ip'] || 
                   req.ip || 
                   req.connection.remoteAddress;
  
  // Check if the request is from localhost or internal
  const isLocalhost = clientIP === '127.0.0.1' || 
                     clientIP === '::1' ||
                     clientIP === '::ffff:127.0.0.1' ||
                     clientIP === 'localhost' ||
                     clientIP.startsWith('192.168.') ||
                     clientIP.startsWith('10.') ||
                     clientIP.startsWith('172.');
  
  // Check if the csvUrl starts with 'https://csvlint.io' (internal validation)
  const isInternalValidation = csvUrl.startsWith('https://csvlint.io');
  
  // Skip rate limiting for localhost, internal IPs, and internal validations
  if (isLocalhost || isInternalValidation) {
    next();
  } else {
    // Apply the rate limiter for external requests
    limiter(req, res, next);
  }
};

// Set view engine to EJS
app.set('view engine', 'ejs');

// CORS configuration for different endpoints
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3080'],
  credentials: true
}));

// Special CORS configuration for validation endpoints to allow badge embedding
app.use('/validate', cors({
  origin: true, // Allow all origins for badge embedding
  credentials: false,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Accept']
}));

// Special CORS configuration for validation report endpoints
app.use('/validation', cors({
  origin: true, // Allow all origins for validation reports
  credentials: false,
  methods: ['GET'],
  allowedHeaders: ['Content-Type', 'Accept']
}));

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

app.get('/dashboard', (req, res) => {
  res.render('dashboard');
});

app.get('/about', (req, res) => {
  res.render('about');
});

app.get('/examples', (req, res) => {
  res.render('examples');
});

// Route to serve example files with CORS enabled
app.get('/examples/:filename', cors({
  origin: true,
  credentials: false
}), (req, res) => {
  try {
    const filename = req.params.filename;
    
    // Validate filename to prevent directory traversal
    if (!filename || filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
      return res.status(400).json({ error: 'Invalid filename' });
    }
    
    const filePath = path.join(__dirname, 'public', 'examples', filename);
    
    // Check if file exists
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    // Set appropriate content type based on file extension
    const ext = path.extname(filename).toLowerCase();
    let contentType = 'text/plain';
    
    switch (ext) {
      case '.csv':
        contentType = 'text/csv';
        break;
      case '.json':
        contentType = 'application/json';
        break;
      case '.tsv':
        contentType = 'text/tab-separated-values';
        break;
      case '.txt':
        contentType = 'text/plain';
        break;
    }
    
    // Set headers
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'public, max-age=3600'); // Cache for 1 hour
    
    // Send the file
    res.sendFile(filePath);
    
  } catch (error) {
    console.error('Error serving example file:', error);
    res.status(500).json({ error: 'Failed to serve file' });
  }
});

app.get('/privacy', (req, res) => {
  res.render('privacy');
});

app.get('/validation/:id', async (req, res) => {
  try {
    // Validate ID format
    if (!validator.isMongoId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid validation ID format' });
    }
    
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

app.get('/dashboard-data', async (req, res) => {
  try {
    // Query to filter documents where "validation.type" is set
    const reports = await ValidationReport.find(
      { "validation.type": { $exists: true } }, // Ensure "validation.type" exists
      {
        _id: 0,
        createdAt: 1,
        validationCount: 1,
        "validation.sourcePresent": 1,
        "validation.schemaPresent": 1,
        "validation.valid": 1,
        "validation.type": 1, // Include validation.type in the projection
        "validation.errors.type": 1,
        "validation.errors.category": 1
      }
    );

    res.json(reports);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// Helper function to extract the domain from a URL
function extractDomain(url) {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.hostname; // Returns the domain (e.g., "example.com")
  } catch (error) {
    return null; // Return null if parsing fails
  }
}

app.get('/validate', conditionalRateLimit, async (req, res) => {
  let csvPath, schemaPath;
  try {
    const csvUrl = req.query.csvUrl || '';
    const schemaUrl = req.query.schemaUrl || '';
    
    // Validate URLs
    if (csvUrl && !validateUrl(csvUrl)) {
      return res.status(400).json({ error: 'Invalid CSV URL provided' });
    }
    
    if (schemaUrl && !validateUrl(schemaUrl)) {
      return res.status(400).json({ error: 'Invalid schema URL provided' });
    }
    
    // Validate that CSV URL points to a CSV file
    if (csvUrl) {
      const csvValidation = await validateCsvUrl(csvUrl);
      if (!csvValidation.isValid) {
        return res.status(400).json({ error: csvValidation.reason });
      }
    }
    
    // Extract domains if URLs are provided
    const sourceDomain = csvUrl ? extractDomain(csvUrl) : null;
    const schemaDomain = schemaUrl ? extractDomain(schemaUrl) : null;

    const format = sanitizeInput(req.query.format); // Get the desired format (svg or png)
    
    // Validate format parameter
    if (format && !['svg', 'png'].includes(format)) {
      return res.status(400).json({ error: 'Invalid format parameter' });
    }

    // Generate the hash
    const hash = generateHash(csvUrl, schemaUrl);

    const form = new FormData();

    if (csvUrl) {
      const lengthResponse = await axios.head(csvUrl, {
        timeout: 10000, // 10 second timeout
        maxRedirects: 5
      });
      const contentLength = parseInt(lengthResponse.headers['content-length'], 10);

      if (contentLength > MAX_FILE_SIZE) {
        return res.status(400).json({ error: 'CSV file size exceeds the allowed limit' });
      }
      form.append('csvUrl', csvUrl);
    }

    if (schemaUrl) {
      const lengthResponse = await axios.head(schemaUrl, {
        timeout: 10000, // 10 second timeout
        maxRedirects: 5
      });
      const contentLength = parseInt(lengthResponse.headers['content-length'], 10);

      if (contentLength > MAX_FILE_SIZE) {
        return res.status(400).json({ error: 'Schema file size exceeds the allowed limit' });
      }
      form.append('schemaUrl', schemaUrl);
    }

    // Collect and sanitize dialect options from the query params
    const dialect = {};
    const dialectParams = ['delimiter', 'doubleQuote', 'lineTerminator', 'nullSequence', 'quoteChar', 'escapeChar', 'skipInitialSpace', 'header', 'caseSensitiveHeader'];
    
    dialectParams.forEach(param => {
      if (req.query[param]) {
        const value = sanitizeInput(req.query[param]);
        if (param === 'doubleQuote' || param === 'skipInitialSpace' || param === 'header' || param === 'caseSensitiveHeader') {
          dialect[param] = value === 'true';
        } else {
          dialect[param] = value;
        }
      }
    });

    if (Object.keys(dialect).length > 0) {
      form.append('dialect', JSON.stringify(dialect));
    }

    // Send the form data to the Ruby server
    const response = await axios.post(CSVLINT_API, form, {
      headers: form.getHeaders(),
      timeout: 30000 // 30 second timeout
    });

    // Prepare validation data for storage
    const validationDataForStorage = getValidationDataForStorage(
      response,
      csvUrl,
      schemaUrl
    );
    validationDataForStorage.sourceDomain = sourceDomain;
    validationDataForStorage.schemaDomain = schemaDomain;
    validationDataForStorage.validation.type = 'url';
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
  // Get the real IP address, considering forwarded headers
  const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                   req.headers['x-real-ip'] || 
                   req.ip || 
                   req.connection.remoteAddress;
  
  // Check if the request is from localhost or internal
  const isLocalhost = clientIP === '127.0.0.1' || 
                     clientIP === '::1' ||
                     clientIP === '::ffff:127.0.0.1' ||
                     clientIP === 'localhost' ||
                     clientIP.startsWith('192.168.') ||
                     clientIP.startsWith('10.') ||
                     clientIP.startsWith('172.');
  
  // Skip rate limiting for localhost and internal IPs
  if (isLocalhost) {
    next();
  } else {
    // Apply rate limiting for external requests
    limiter(req, res, next);
  }
}, (req, res, next) => {
  upload.fields([{ name: 'file' }, { name: 'schema' }])(req, res, (err) => {
    if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File size exceeds the allowed limit of 10mb' });
    } else if (err && err.message && err.message.includes('Invalid')) {
      // Handle file type validation errors
      return res.status(400).json({ error: err.message });
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

      // Debug: Log what we received
      /*
      console.log('POST /validate - Request received:');
      console.log('Body:', req.body);
      console.log('Files:', req.files);
      console.log('csvUrl:', req.body.csvUrl);
      console.log('schemaUrl:', req.body.schemaUrl);
      */
      // Get URLs without sanitization (they're validated separately)
      const csvUrl = req.body.csvUrl;
      const schemaUrl = req.body.schemaUrl;

      // Determine if both inputs are URLs
      const isCsvUrl = Boolean(csvUrl);
      const isSchemaUrl = Boolean(schemaUrl);

      // Validate URLs if provided
      if (isCsvUrl && !validateUrl(csvUrl)) {
        return res.status(400).json({ error: 'Invalid CSV URL provided' });
      }
      
      if (isSchemaUrl && !validateUrl(schemaUrl)) {
        return res.status(400).json({ error: 'Invalid schema URL provided' });
      }

      // Validate that CSV URL points to a CSV file
      if (isCsvUrl) {
        const csvValidation = await validateCsvUrl(csvUrl);
        if (!csvValidation.isValid) {
          return res.status(400).json({ error: csvValidation.reason });
        }
      }

      // Check if we have either CSV URL or file
      const hasCsvInput = isCsvUrl || (req.files && req.files.file);
      if (!hasCsvInput) {
        return res.status(400).json({ error: 'Please provide either a CSV URL or upload a CSV file' });
      }

      // Check if we have both URL and file for CSV (should not happen)
      if (isCsvUrl && req.files && req.files.file) {
        return res.status(400).json({ error: 'Please provide either a CSV URL OR upload a CSV file, not both' });
      }

      // Extract domains if URLs are provided
      const sourceDomain = isCsvUrl ? extractDomain(csvUrl) : null;
      const schemaDomain = isSchemaUrl ? extractDomain(schemaUrl) : null;
      // Determine the type of validation
      const validationType = isCsvUrl ? 'url' : 'file';

      if (isCsvUrl) {
        const lengthResponse = await axios.head(csvUrl, {
          timeout: 10000,
          maxRedirects: 5
        });
        const contentLength = parseInt(lengthResponse.headers['content-length'], 10);

        if (contentLength > MAX_FILE_SIZE) {
          return res.status(400).json({ error: 'CSV file size exceeds the allowed limit' });
        }
        form.append('csvUrl', csvUrl);
      } else if (req.files.file) {
        csvPath = req.files.file[0].path;
        form.append('file', fs.createReadStream(csvPath));

        // Generate hash from file contents
        hash = await generateFileHash(csvPath);
      }

      if (isSchemaUrl) {
        const lengthResponse = await axios.head(schemaUrl, {
          timeout: 10000,
          maxRedirects: 5
        });
        const contentLength = parseInt(lengthResponse.headers['content-length'], 10);

        if (contentLength > MAX_FILE_SIZE) {
          return res.status(400).json({ error: 'Schema file size exceeds the allowed limit' });
        }
        form.append('schemaUrl', schemaUrl);
      } else if (req.files.schema) {
        form.append('schema', fs.createReadStream(req.files.schema[0].path));
        schemaPath = req.files.schema[0].path;
      }

      let isEmbedAllowed = false;

      // Only generate a hash if both inputs are URLs or schema is not provided
      if (isCsvUrl && !req.files.schema) {
        hash = generateHash(csvUrl, schemaUrl);
        isEmbedAllowed = true;
      }

      // Collect and sanitize dialect options from the form data, only if explicitly set
      const dialect = {};
      const dialectParams = ['delimiter', 'doubleQuote', 'lineTerminator', 'nullSequence', 'quoteChar', 'escapeChar', 'skipInitialSpace', 'header', 'caseSensitiveHeader'];
      
      dialectParams.forEach(param => {
        if (req.body[param]) {
          const value = sanitizeInput(req.body[param]);
          if (param === 'doubleQuote' || param === 'skipInitialSpace' || param === 'header' || param === 'caseSensitiveHeader') {
            dialect[param] = value === 'true';
          } else {
            dialect[param] = value;
          }
        }
      });

      // Only send the dialect if it has properties set
      if (Object.keys(dialect).length > 0) {
        form.append('dialect', JSON.stringify(dialect));
      }
      // Send the form data to the Ruby server
      const response = await axios.post(CSVLINT_API, form, {
        headers: form.getHeaders(),
        timeout: 30000
      });

      // Clean up temp files
      if (csvPath) fs.unlinkSync(csvPath);
      if (schemaPath) fs.unlinkSync(schemaPath);

      const validationDataForStorage = getValidationDataForStorage(
        response,
        csvUrl || csvPath,
        schemaUrl || schemaPath
      );

      // Set the hash in the validation data if it was generated
      validationDataForStorage.hash = hash;
      if (isCsvUrl) {
        validationDataForStorage.sourceDomain = sourceDomain;
        validationDataForStorage.schemaDomain = schemaDomain;
      }
      validationDataForStorage.validation.type = validationType;

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
        csvUrl || csvPath,
        schemaUrl || schemaPath
      );

      response.data.info = response.data.info_messages;
      delete(response.data.info_messages);
      const humanResponse = getHumanReadableMessages(response.data);
      humanResponse.id = id;

      if (req.headers.accept && req.headers.accept.includes('application/json')) {
        // Send JSON response for API
        res.json(JSONResponse);
      } else {
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
      try {
        if (csvPath) fs.unlinkSync(csvPath);
      } catch (unlinkError) {
        //Assume not there
      }

      try {
        if (schemaPath) fs.unlinkSync(schemaPath);
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

// Function to generate hash from file contents
async function generateFileHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);

    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', (err) => reject(err));
  });
}

// Start server
app.listen(port , () => console.log('App listening on port ' + port));