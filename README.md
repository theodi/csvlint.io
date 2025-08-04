# CSVLint.io

CSVLint is an online validation tool for CSV files. It validates CSV files for conformity to standards, checks for missing or malformed data, and can validate against both [CSV on the Web (CSVW)](https://www.w3.org/TR/tabular-data-model/) and [Data Package](https://specs.frictionlessdata.io/data-package/) schema standards. CSVLint is developed and maintained by the [Open Data Institute](https://theodi.org).

## Features

- **CSV Structure Validation**: Checks CSV files for proper formatting, delimiters, and structural integrity.
- **Schema Validation**: Validates CSV data against specified schemas, including CSVW and Data Package standards, to ensure that data formats, types, and constraints are met.
- **Error Reporting**: Provides detailed error messages and warnings to help users identify and fix issues in their CSV files.
- **URL and File Upload Validation**: Validates CSV files available via URL or directly uploaded.
- **Dialect Support**: Supports various CSV dialects and formatting options.
- **Privacy-Focused**: Does not store URLs or CSV content after validation. Instead, a one-way hash of URLs is stored to identify previously validated URLs without retaining identifiable data.

## Security Features

This application includes comprehensive security measures to protect against:

- **File Upload Attacks**: Server-side file type validation, MIME type checking, and size limits
- **SSRF Protection**: URL validation that blocks dangerous protocols and private IP ranges
- **XSS Prevention**: Input sanitization and Content Security Policy headers
- **Rate Limiting**: IP-based rate limiting to prevent abuse
- **Security Headers**: Comprehensive security headers via Helmet.js
- **Input Validation**: All user inputs are validated and sanitized

For detailed security information, see [SECURITY.md](SECURITY.md).

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-repo/csvlint.io.git
cd csvlint.io
```

2. Install dependencies:
```bash
npm install
```

3. Create a configuration file:
```bash
cp config.env.example config.env
```

4. Edit `config.env` with your settings:
```env
# Server config
PORT=3080
HOST=http://localhost:3080

# MONGO DB config
MONGO_URI=mongodb://localhost:27017/csvlint
MONGO_DB=csvlint

# Wrapper location for CSVLint.rb gem
CSVLINT_API = http://localhost:4567/validate

# Security Configuration
ALLOWED_ORIGINS=http://localhost:3080,https://csvlint.io
HASH_SECRET=your_secure_random_secret_key_here
```

5. Start the application:
```bash
npm start
```

## Security Testing

Run the security test suite to verify all security measures are working:

```bash
npm run security-test
```

This will test:
- Security headers
- File upload validation
- URL validation
- Rate limiting
- Input sanitization
- MongoDB ID validation

## API Usage

The CSVLint API can be used programmatically to validate CSV files via URLs or direct file uploads.

### Endpoints

- **POST /validate**: Validates a CSV file from a URL or uploaded file.
- **GET /validate**: Validates a CSV from a URL and returns either a badge or JSON report based on `format` and `accept` headers.

### Parameters

- **csvUrl** (string): URL to the CSV file to validate.
- **schemaUrl** (string): URL to a JSON schema for validation (optional).
- **file** (file): CSV file upload (optional, if `csvUrl` is provided).
- **schema** (file): JSON schema file upload (optional).

### Example Usage

```bash
# Validate a CSV from URL
curl -X POST http://csvlint.io/validate \
  -H "Accept: application/json" \
  -F "csvUrl=http://example.com/mydata.csv" \
  -F "schemaUrl=http://example.com/myschema.json"

# Upload a CSV file
curl -X POST http://csvlint.io/validate \
  -H "Accept: application/json" \
  -F "file=@/path/to/yourfile.csv" \
  -F "schema=@/path/to/yourschema.json"
```

## Response Format

The API can return a JSON response or validation badge depending on the `format` query parameter or `accept` header.

### JSON Response Example

```json
{
  "id": "507f1f77bcf86cd799439011",
  "version": "0.2",
  "licence": "http://opendatacommons.org/licenses/odbl/",
  "validation": {
    "source": "http://example.com/mydata.csv",
    "schema": "http://example.com/myschema.json",
    "valid": true,
    "errors": [],
    "warnings": [],
    "info": []
  }
}
```

### Badge Integration

You can embed validation badges on your website:

```html
<a href="https://csvlint.io/validate?csvUrl=http://example.com/mydata.csv">
  <img src="https://csvlint.io/validate?csvUrl=http://example.com/mydata.csv&format=svg" alt="Validation Badge">
</a>
```

## Privacy and Data Retention

- **File Uploads**: Files are deleted immediately after validation
- **URL Privacy**: URLs are hashed and not stored in plain text
- **No Content Storage**: File contents are never stored
- **Validation Reports**: Only anonymized validation results are retained

## Security Considerations

- All file uploads are validated for type and size
- URLs are validated to prevent SSRF attacks
- Input sanitization prevents XSS attacks
- Rate limiting prevents abuse
- Security headers protect against various attacks

For detailed security information, see [SECURITY.md](SECURITY.md).

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run security tests: `npm run security-test`
5. Submit a pull request

## License

This project is licensed under the ISC License.

## Support

For support and questions:
- Email: support@csvlint.io
- GitHub Issues: [Repository Issues](https://github.com/your-repo/issues)

For security issues:
- Email: security@csvlint.io
- Please include "SECURITY" in the subject line
