/**
 * Verification script for rate limiting 429 response
 * Tests that excessive requests return 429 Too Many Requests
 */

const http = require('http');

const BASE_URL = 'http://localhost:3001';
const ENDPOINT = '/api/verify/proof';

// Configuration
const MAX_REQUESTS = 60; // More than the 50 limit
const DELAY_MS = 10; // Small delay between requests

async function makeRequest(requestNumber) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'localhost',
      port: 3001,
      path: '/api/verify/proof',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      }
    };

    const req = http.request(options, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        try {
          const responseBody = JSON.parse(data);
          resolve({
            status: res.statusCode,
            body: responseBody
          });
        } catch (e) {
          resolve({
            status: res.statusCode,
            body: data
          });
        }
      });
    });

    req.on('error', (err) => {
      reject(err);
    });

    // Send minimal valid request body to avoid validation errors
    const requestBody = {
      proofs: [],
      sessionId: `test-session-${requestNumber}`,
      token: `test-token-${requestNumber}`,
      domain: 'example.com',
      verificationType: 'test'
    };

    req.write(JSON.stringify(requestBody));
    req.end();
  });
}

async function runTest() {
  console.log('🚀 Starting rate limit test...');
  console.log(`📍 Target: ${BASE_URL}${ENDPOINT}`);
  console.log(`🎯 Sending ${MAX_REQUESTS} requests`);

  const results = [];
  let successCount = 0;
  let rateLimitCount = 0;

  for (let i = 1; i <= MAX_REQUESTS; i++) {
    try {
      console.log(`📤 Request ${i}/${MAX_REQUESTS}`);
      const result = await makeRequest(i);
      results.push(result);

      if (result.status === 429) {
        rateLimitCount++;
        console.log(`❌ Request ${i}: ${result.status} - Rate limited`);
      } else if (result.status < 400 || result.status === 400 || result.status === 409) {
        // Accept success or validation errors as valid responses
        successCount++;
        console.log(`✅ Request ${i}: ${result.status} - Allowed`);
      } else {
        console.log(`⚠️  Request ${i}: ${result.status} - Unexpected error`);
      }

      // Small delay between requests
      if (i < MAX_REQUESTS) {
        await new Promise(resolve => setTimeout(resolve, DELAY_MS));
      }

    } catch (error) {
      console.error(`💥 Request ${i} failed:`, error.message);
      results.push({ status: 'ERROR', error: error.message });
    }
  }

  // Analyze results
  console.log('\n📊 Test Results:');
  console.log(`✅ Successful requests: ${successCount}`);
  console.log(`❌ Rate limited requests: ${rateLimitCount}`);
  console.log(`📈 Total requests: ${results.length}`);

  // Check if the test passes
  const hasRateLimiting = rateLimitCount > 0;
  const hasSomeSuccess = successCount > 0;

  console.log('\n🎯 Test Criteria:');
  console.log(`- Should have some successful requests: ${hasSomeSuccess ? '✅' : '❌'}`);
  console.log(`- Should have rate limited requests: ${hasRateLimiting ? '✅' : '❌'}`);

  if (hasRateLimiting && hasSomeSuccess) {
    console.log('\n🎉 TEST PASSED: Rate limiting is working correctly!');
    process.exit(0);
  } else {
    console.log('\n💥 TEST FAILED: Rate limiting not working as expected');
    console.log('Expected: Some requests succeed, some return 429');
    console.log(`Got: ${successCount} success, ${rateLimitCount} rate limited`);
    process.exit(1);
  }
}

// Validate environment before running
console.log('🔍 Validating environment...');
require('http').get('http://localhost:3001/health', (res) => {
  if (res.statusCode === 200) {
    console.log('✅ Server is healthy');
    runTest();
  } else {
    console.error('❌ Server not healthy. Status:', res.statusCode);
    process.exit(1);
  }
}).on('error', (err) => {
  console.error('❌ Cannot connect to server:', err.message);
  console.log('💡 Make sure the backend server is running on port 3001');
  process.exit(1);
});