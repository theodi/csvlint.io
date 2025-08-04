#!/usr/bin/env node

/**
 * Security Test Script for CSVLint.io
 * Run this script to test various security measures
 * 
 * Usage:
 *   node security-test.js                    # Run all tests
 *   node security-test.js examples           # Run only examples route test
 *   node security-test.js rate-limiting      # Run only rate limiting tests
 *   node security-test.js headers            # Run only security headers test
 */

const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');
// Load environment variables securely
require("dotenv").config({ path: "./config.env" });

const BASE_URL = process.env.TEST_URL || 'http://localhost:3080';

// Test results
const results = {
  passed: 0,
  failed: 0,
  tests: []
};

function logTest(name, passed, details = '') {
  const status = passed ? '✅ PASS' : '❌ FAIL';
  console.log(`${status}: ${name}`);
  if (details) console.log(`   ${details}`);
  
  results.tests.push({ name, passed, details });
  if (passed) results.passed++;
  else results.failed++;
}

async function testSecurityHeaders() {
  try {
    const response = await axios.get(`${BASE_URL}/`);
    
    const requiredHeaders = [
      'x-frame-options',
      'x-content-type-options',
      'x-xss-protection',
      'strict-transport-security'
    ];
    
    let allPresent = true;
    requiredHeaders.forEach(header => {
      if (!response.headers[header]) {
        allPresent = false;
      }
    });
    
    logTest('Security Headers', allPresent, 
      allPresent ? 'All required security headers present' : 'Missing security headers');
  } catch (error) {
    logTest('Security Headers', false, `Error: ${error.message}`);
  }
}

async function testFileUploadValidation() {
  try {
    // Test with non-CSV file
    const form = new FormData();
    const testFile = path.join(__dirname, 'package.json');
    form.append('file', fs.createReadStream(testFile));
    
    const response = await axios.post(`${BASE_URL}/validate`, form, {
      headers: form.getHeaders()
    });
    
    // Should fail with non-CSV file
    logTest('File Upload Validation', false, 'Non-CSV file was accepted');
  } catch (error) {
   
    if (error.response && error.response.status === 400) {
      logTest('File Upload Validation', true, 'Non-CSV file correctly rejected');
    } else if (error.response && error.response.status === 500) {
      logTest('File Upload Validation', false, `Server error (500): ${JSON.stringify(error.response.data)}`);
    } else {
      logTest('File Upload Validation', false, `Unexpected error: ${error.message}`);
    }
  }
}

async function testUrlValidation() {
  const maliciousUrls = [
    'file:///etc/passwd',
    'data:text/html,<script>alert("xss")</script>',
    'javascript:alert("xss")',
    'http://localhost:8080/test.csv', // Different port - should be blocked
    'http://192.168.1.1/test.csv'
  ];
  
  for (const url of maliciousUrls) {
    try {
      const response = await axios.get(`${BASE_URL}/validate?csvUrl=${encodeURIComponent(url)}`);
      logTest(`URL Validation - ${url}`, false, 'Malicious URL was accepted');
    } catch (error) {
      if (error.response && error.response.status === 400) {
        logTest(`URL Validation - ${url}`, true, 'Malicious URL correctly rejected');
      } else {
        logTest(`URL Validation - ${url}`, false, `Unexpected error: ${error.message}`);
      }
    }
  }
  
  // Test that localhost URLs pointing to our own server are allowed
  try {
    const ownServerUrl = `${BASE_URL}/examples/students_perfect.csv`;
    const response = await axios.get(`${BASE_URL}/validate?csvUrl=${encodeURIComponent(ownServerUrl)}`);
    logTest('URL Validation - Own Server URL', true, 'Own server URL correctly allowed');
  } catch (error) {
    if (error.response && error.response.status === 400) {
      logTest('URL Validation - Own Server URL', false, 'Own server URL incorrectly rejected');
    } else {
      logTest('URL Validation - Own Server URL', true, 'Own server URL allowed (other error expected)');
    }
  }
}

async function testRateLimiting() {
  try {
    // Test rate limiting by making requests from a single external IP
    const testIP = `203.0.113.${Math.floor(Math.random() * 255)}`; // Random IP to avoid conflicts
    const promises = [];
    
    // Make 105 requests (exceeding the 100 limit)
    for (let i = 0; i < 105; i++) {
      promises.push(axios.get(`${BASE_URL}/validate?csvUrl=https://example.com/test.csv`, {
        headers: {
          'X-Forwarded-For': testIP,
          'X-Real-IP': testIP
        }
      }));
    }
    
    const responses = await Promise.allSettled(promises);
    const successful = responses.filter(r => r.status === 'fulfilled').length;
    const rateLimited = responses.filter(r => 
      r.status === 'rejected' && r.reason.response && r.reason.response.status === 429
    ).length;
    
    // Check if rate limiting is working (should have some rate limited requests)
    const isWorking = rateLimited > 0;
    
    logTest('Rate Limiting', isWorking, 
      `Rate limiting test: ${rateLimited} requests rate limited, ${successful} successful from IP ${testIP}`);
  } catch (error) {
    logTest('Rate Limiting', false, `Error: ${error.message}`);
  }
}

async function testLocalhostRateLimitExemption() {
  try {
    // Test that localhost requests are not rate limited
    const promises = [];
    for (let i = 0; i < 110; i++) {
      promises.push(axios.get(`${BASE_URL}/validate?csvUrl=https://example.com/test.csv`, {
        headers: {
          'X-Forwarded-For': '127.0.0.1', // Simulate localhost
          'X-Real-IP': '127.0.0.1'
        }
      }));
    }
    
    const responses = await Promise.allSettled(promises);
    const rateLimited = responses.filter(r => 
      r.status === 'rejected' && r.reason.response && r.reason.response.status === 429
    ).length;
    
    logTest('Localhost Rate Limit Exemption', rateLimited === 0, 
      rateLimited === 0 ? 'Localhost requests correctly exempt from rate limiting' : `${rateLimited} localhost requests were incorrectly rate limited`);
  } catch (error) {
    logTest('Localhost Rate Limit Exemption', false, `Error: ${error.message}`);
  }
}

async function testInputSanitization() {
  try {
    const maliciousInput = '<script>alert("xss")</script>';
    const response = await axios.get(`${BASE_URL}/validate?csvUrl=${encodeURIComponent(maliciousInput)}`);
    
    // Check if the response contains the malicious input
    const responseText = JSON.stringify(response.data);
    const containsMaliciousInput = responseText.includes(maliciousInput);
    
    logTest('Input Sanitization', !containsMaliciousInput, 
      containsMaliciousInput ? 'Malicious input not sanitized' : 'Input properly sanitized');
  } catch (error) {
    if (error.response && error.response.status === 400) {
      logTest('Input Sanitization', true, 'Malicious input correctly rejected');
    } else {
      logTest('Input Sanitization', false, `Error: ${error.message}`);
    }
  }
}

async function testMongoIdValidation() {
  try {
    const invalidId = 'invalid-id-format';
    const response = await axios.get(`${BASE_URL}/validation/${invalidId}`);
    
    logTest('MongoDB ID Validation', false, 'Invalid ID format was accepted');
  } catch (error) {
    if (error.response && error.response.status === 400) {
      logTest('MongoDB ID Validation', true, 'Invalid ID format correctly rejected');
    } else {
      logTest('MongoDB ID Validation', false, `Error: ${error.message}`);
    }
  }
}

async function testCorsForBadgeEmbedding() {
  try {
    // Test that validation endpoints allow cross-origin requests
    const response = await axios.get(`${BASE_URL}/validate?csvUrl=https://example.com/test.csv&format=svg`, {
      headers: {
        'Origin': 'https://external-site.com',
        'Accept': 'image/svg+xml'
      }
    });
    console.log(response);
    // Check for CORS headers
    const hasCorsHeaders = response.headers['access-control-allow-origin'] || 
                          response.headers['Access-Control-Allow-Origin'];
    
    logTest('CORS for Badge Embedding', hasCorsHeaders, 
      hasCorsHeaders ? 'CORS headers present for badge embedding' : 'Missing CORS headers for badge embedding');
  } catch (error) {
    if (error.response && error.response.status === 400) {
      // This is expected for invalid URL, but CORS headers should still be present
      const hasCorsHeaders = error.response.headers['access-control-allow-origin'] || 
                            error.response.headers['Access-Control-Allow-Origin'];
      logTest('CORS for Badge Embedding', hasCorsHeaders, 
        hasCorsHeaders ? 'CORS headers present even for error responses' : 'Missing CORS headers for error responses');
    } else {
      logTest('CORS for Badge Embedding', false, `Error: ${error.message}`);
    }
  }
}

async function testExamplesRoute() {
  try {
    // Test that example files are served correctly
    const response = await axios.get(`${BASE_URL}/examples/students_perfect.csv`);
    
    const isSuccessful = response.status === 200 && 
                        response.headers['content-type'].includes('text/csv') &&
                        response.data.includes('Name,Age');

    logTest('Examples Route', isSuccessful, 
      isSuccessful ? 'Example files served correctly with proper content type' : 'Example files not served correctly');
  } catch (error) {
    logTest('Examples Route', false, `Error: ${error.message}`);
  }
}

async function testCsvUrlValidation() {
  const nonCsvUrls = [
    'https://theodi.cdn.ngo/media/images/odi_and_solid_web-large-734x469.2e16d0ba.fill-665x402.png',
    'https://example.com/document.pdf',
    'https://example.com/image.jpg',
    'https://example.com/script.js',
    'https://example.com/data.json'
  ];
  
  for (const url of nonCsvUrls) {
    try {
      const response = await axios.get(`${BASE_URL}/validate?csvUrl=${encodeURIComponent(url)}`);
      logTest(`CSV URL Validation - ${url}`, false, 'Non-CSV URL was accepted');
    } catch (error) {
      if (error.response && error.response.status === 400) {
        logTest(`CSV URL Validation - ${url}`, true, 'Non-CSV URL correctly rejected');
      } else {
        logTest(`CSV URL Validation - ${url}`, false, `Unexpected error: ${error.message}`);
      }
    }
  }
  
  // Test that valid CSV URLs are accepted
  try {
    const validCsvUrl = `${BASE_URL}/examples/students_perfect.csv`;
    const response = await axios.get(`${BASE_URL}/validate?csvUrl=${encodeURIComponent(validCsvUrl)}`);
    logTest('CSV URL Validation - Valid CSV', true, 'Valid CSV URL correctly accepted');
  } catch (error) {
    if (error.response && error.response.status === 400) {
      logTest('CSV URL Validation - Valid CSV', false, 'Valid CSV URL incorrectly rejected');
    } else {
      logTest('CSV URL Validation - Valid CSV', true, 'Valid CSV URL accepted (other error expected)');
    }
  }
}

// Test mapping
const testFunctions = {
  'headers': testSecurityHeaders,
  'file-upload': testFileUploadValidation,
  'url-validation': testUrlValidation,
  'rate-limiting': testRateLimiting,
  'localhost-exemption': testLocalhostRateLimitExemption,
  'input-sanitization': testInputSanitization,
  'mongo-id': testMongoIdValidation,
  'cors': testCorsForBadgeEmbedding,
  'examples': testExamplesRoute,
  'csv-url-validation': testCsvUrlValidation
};

async function runAllTests() {
  console.log('🔒 Running Security Tests for CSVLint.io\n');
  
  await testSecurityHeaders();
  await testFileUploadValidation();
  await testUrlValidation();
  await testRateLimiting();
  await testLocalhostRateLimitExemption();
  await testInputSanitization();
  await testMongoIdValidation();
  await testCorsForBadgeEmbedding();
  await testExamplesRoute();
  await testCsvUrlValidation();
  
  console.log('\n📊 Test Summary:');
  console.log(`✅ Passed: ${results.passed}`);
  console.log(`❌ Failed: ${results.failed}`);
  console.log(`📈 Success Rate: ${((results.passed / (results.passed + results.failed)) * 100).toFixed(1)}%`);
  
  if (results.failed > 0) {
    console.log('\n⚠️  Security issues detected! Please review and fix the failed tests.');
    process.exit(1);
  } else {
    console.log('\n🎉 All security tests passed!');
  }
}

async function runSpecificTest(testName) {
  const testFunction = testFunctions[testName];
  if (!testFunction) {
    console.log(`❌ Unknown test: ${testName}`);
    console.log('Available tests:');
    Object.keys(testFunctions).forEach(test => console.log(`  - ${test}`));
    process.exit(1);
  }
  
  console.log(`🔒 Running ${testName} test for CSVLint.io\n`);
  
  await testFunction();
  
  console.log('\n📊 Test Summary:');
  console.log(`✅ Passed: ${results.passed}`);
  console.log(`❌ Failed: ${results.failed}`);
  
  if (results.failed > 0) {
    console.log('\n⚠️  Test failed!');
    process.exit(1);
  } else {
    console.log('\n🎉 Test passed!');
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  const testName = process.argv[2];
  
  if (testName) {
    runSpecificTest(testName).catch(console.error);
  } else {
    runAllTests().catch(console.error);
  }
}

module.exports = {
  runAllTests,
  runSpecificTest,
  testFunctions,
  results
}; 