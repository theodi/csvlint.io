# Security Documentation for CSVLint.io

## Overview
This document outlines the security measures implemented in the CSVLint.io application to protect against file injection, abuse, and other security vulnerabilities.

## Security Vulnerabilities Addressed

### 1. File Upload Security
- **File Type Validation**: Implemented server-side validation for uploaded files
- **MIME Type Checking**: Validates both file extension and MIME type
- **File Size Limits**: 10MB maximum file size
- **File Count Limits**: Maximum 2 files per request (CSV + schema)
- **Temporary File Cleanup**: Files are deleted immediately after processing

### 2. URL Validation & SSRF Protection

The application implements comprehensive URL validation to prevent Server-Side Request Forgery (SSRF) attacks:

#### Blocked Protocols
- `file:` - Prevents access to local files
- `data:` - Prevents data URI attacks
- `javascript:` - Prevents script injection
- `vbscript:` - Prevents VBScript injection

#### Blocked IP Ranges
- `localhost` and `127.0.0.1` - Blocked except for our own server
- `::1` (IPv6 localhost) - Blocked except for our own server
- Private IP ranges: `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`

#### Allowed Localhost URLs
- URLs pointing to our own server are allowed for internal functionality
- This enables the examples page to work with local example files
- Only URLs matching our server's host and port are permitted

#### CSV File Validation
- **File Extension Check**: URLs must end with `.csv`, `.tsv`, or `.txt`
- **Content Type Validation**: Server responds with appropriate CSV content types
- **Supported Types**: `text/csv`, `application/csv`, `text/tab-separated-values`, `text/plain`
- **Rejection**: Non-CSV files (images, PDFs, scripts, etc.) are rejected

#### Validation Process
1. URL format validation using `validator.isURL()`
2. Protocol validation against dangerous protocols
3. Hostname validation against blocked IP ranges
4. Special handling for localhost URLs pointing to our own server
5. CSV file validation (extension + content type check)

### 3. Input Sanitization
- **XSS Prevention**: All user inputs are escaped using validator.js
- **Parameter Validation**: Query parameters are validated and sanitized
- **MongoDB ID Validation**: Validation report IDs are checked for proper format

### 4. Security Headers
- **Helmet.js**: Comprehensive security headers
- **Content Security Policy**: Restricts resource loading to same origin only
- **External Scripts**: All JavaScript moved to external files to comply with CSP
- **HSTS**: HTTP Strict Transport Security
- **X-Frame-Options**: Prevents clickjacking
- **X-Content-Type-Options**: Prevents MIME type sniffing

### 5. Rate Limiting
- **IP-based Limiting**: 100 requests per 15 minutes per IP
- **Localhost Exemption**: Development requests from localhost and internal IPs are exempt
- **Conditional Limiting**: Internal requests bypass rate limiting
- **Request Logging**: Rate limit violations are logged

### 6. CORS Configuration
- **Origin Restriction**: Configurable allowed origins via environment variable for main application
- **Badge Embedding**: Open CORS for validation endpoints to allow badge embedding on external websites
- **Examples Route**: Dedicated route for serving example files with CORS enabled
- **Credentials Support**: Proper CORS configuration for credentials where needed

## Environment Variables for Security

Add these to your `config.env` file:

```env
# Security Configuration
ALLOWED_ORIGINS=http://localhost:3080,https://csvlint.io
HASH_SECRET=your_secure_random_secret_key_here
```

## Security Recommendations

### 1. Production Deployment
- Use HTTPS in production
- Set up proper SSL/TLS certificates
- Configure reverse proxy (nginx/Apache) with security headers
- Use environment variables for all sensitive configuration

### 2. Monitoring and Logging
- Implement comprehensive logging for security events
- Monitor for unusual traffic patterns
- Set up alerts for rate limit violations
- Log file upload attempts and validation results

### 3. Additional Security Measures
- Consider implementing API key authentication for high-volume users
- Add request signing for sensitive operations
- Implement file content scanning for malicious content
- Set up automated security scanning

### 4. Database Security
- Use MongoDB authentication
- Restrict database access to application server only
- Regular database backups
- Monitor for unusual database queries

### 5. Network Security
- Use firewall rules to restrict access
- Implement DDoS protection
- Regular security updates for dependencies
- Monitor for suspicious network activity

## Security Testing

### Manual Testing Checklist
- [ ] Test file upload with non-CSV files
- [ ] Test URL validation with malicious URLs
- [ ] Test rate limiting functionality
- [ ] Verify security headers are present
- [ ] Test input sanitization
- [ ] Verify file cleanup after processing

### Automated Testing

The application includes a comprehensive automated security testing suite (`security-test.js`) that validates all security measures:

#### Available Security Tests

**File Upload Security**
```bash
npm run test-file-upload
```
- Tests file type validation (rejects non-CSV files)
- Validates MIME type checking
- Ensures proper error responses

**URL Validation & SSRF Protection**
```bash
npm run test-url-validation
```
- Tests dangerous protocol blocking (`file:`, `data:`, `javascript:`)
- Validates private IP range blocking
- Ensures localhost URLs pointing to own server are allowed
- Tests CSV file validation (extension + content type)

**Rate Limiting**
```bash
npm run test-rate-limiting
npm run test-localhost-exemption
```
- Tests IP-based rate limiting (100 requests per 15 minutes)
- Validates localhost exemption for development
- Ensures proper rate limit headers

**Input Sanitization**
```bash
npm run test-input-sanitization
```
- Tests XSS prevention with malicious input
- Validates HTML entity escaping
- Ensures sanitized output

**Security Headers**
```bash
npm run test-headers
```
- Validates presence of required security headers
- Tests CSP, HSTS, X-Frame-Options, X-Content-Type-Options

**CORS Configuration**
```bash
npm run test-cors
```
- Tests CORS headers for badge embedding
- Validates cross-origin request handling

**MongoDB ID Validation**
```bash
npm run test-mongo-id
```
- Tests MongoDB ID format validation
- Prevents NoSQL injection attacks

**Examples Route**
```bash
npm run test-examples
```
- Tests secure file serving from examples directory
- Validates directory traversal protection
- Tests proper content type headers

**CSV URL Validation**
```bash
npm run test-csv-url-validation
```
- Tests CSV file validation for URLs
- Validates extension and content type checking
- Ensures non-CSV URLs are rejected

#### Running All Tests
```bash
npm run test-all
# or
npm run security-test
```

#### Individual Test Usage
```bash
# Run specific test
node security-test.js examples

# Run with custom test URL
TEST_URL=https://your-server.com node security-test.js

# Available test names:
# - headers
# - file-upload
# - url-validation
# - rate-limiting
# - localhost-exemption
# - input-sanitization
# - mongo-id
# - cors
# - examples
# - csv-url-validation
```

#### Test Output
Tests provide detailed feedback:
- ✅ **PASS**: Security measure working correctly
- ❌ **FAIL**: Security issue detected
- 📊 **Summary**: Success rate and test results
- 🔍 **Details**: Specific error information

#### Continuous Integration
The security tests can be integrated into CI/CD pipelines:
```yaml
# Example GitHub Actions
- name: Run Security Tests
  run: npm run test-all
```

#### Test Coverage
The security test suite covers:
- File upload validation and security
- URL validation and SSRF protection
- Input sanitization and XSS prevention
- Rate limiting and abuse prevention
- Security headers and CSP compliance
- CORS configuration for badge embedding
- MongoDB ID validation
- Directory traversal protection
- CSV file validation for URLs

## Dependencies Security

### Current Security Dependencies
- `helmet`: Security headers
- `validator`: Input validation and sanitization
- `express-rate-limit`: Rate limiting
- `multer`: File upload with validation

### Regular Updates
- Run `npm audit` regularly
- Update dependencies with security patches
- Monitor security advisories for used packages

## Compliance Considerations

### Data Protection
- No personal data is stored
- File contents are not retained
- URLs are hashed for privacy
- Validation reports contain no sensitive information

### Privacy
- Files are deleted immediately after processing
- No file content is stored
- URLs are not stored in plain text
- Validation reports are anonymized