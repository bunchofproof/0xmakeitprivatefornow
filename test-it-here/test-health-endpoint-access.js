/**
 * Test script to verify that the /health endpoint works without Content-Length validation errors
 * This script tests the fix for the "Invalid content-length header" error that was blocking GET requests.
 */

const http = require('http');

// Configuration
const BACKEND_HOST = 'localhost';
const BACKEND_PORT = 3001;
const HEALTH_ENDPOINT = '/health';

// Test function
function testHealthEndpoint() {
  return new Promise((resolve, reject) => {
    console.log('Testing /health endpoint access...');

    const options = {
      hostname: BACKEND_HOST,
      port: BACKEND_PORT,
      path: HEALTH_ENDPOINT,
      method: 'GET',
      headers: {
        'User-Agent': 'Test-Script/1.0'
        // Intentionally not setting Content-Length to test the fix
      }
    };

    const req = http.request(options, (res) => {
      let data = '';

      console.log(`Response status: ${res.statusCode}`);
      console.log(`Response headers:`, res.headers);

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        console.log('Response received successfully');
        console.log('Response body:', data);

        if (res.statusCode === 200) {
          console.log('✅ SUCCESS: /health endpoint returned 200 OK');
          resolve({
            success: true,
            statusCode: res.statusCode,
            body: data,
            headers: res.headers
          });
        } else {
          console.log(`❌ FAILURE: Expected 200, got ${res.statusCode}`);
          resolve({
            success: false,
            statusCode: res.statusCode,
            body: data,
            headers: res.headers
          });
        }
      });
    });

    req.on('error', (err) => {
      console.error('❌ FAILURE: Request failed with error:', err.message);
      reject(err);
    });

    req.setTimeout(5000, () => {
      console.error('❌ FAILURE: Request timed out');
      req.destroy();
      reject(new Error('Request timed out'));
    });

    // End the request (no body for GET)
    req.end();
  });
}

// Wait for server to be ready
function waitForServer(maxRetries = 10) {
  return new Promise((resolve, reject) => {
    let retries = 0;

    const checkServer = () => {
      const req = http.request({
        hostname: BACKEND_HOST,
        port: BACKEND_PORT,
        path: '/',
        method: 'HEAD'
      }, (res) => {
        console.log('Server is ready');
        resolve();
      });

      req.on('error', (err) => {
        retries++;
        if (retries >= maxRetries) {
          reject(new Error(`Server not ready after ${maxRetries} retries: ${err.message}`));
        } else {
          console.log(`Waiting for server... (${retries}/${maxRetries})`);
          setTimeout(checkServer, 1000);
        }
      });

      req.setTimeout(2000, () => {
        req.destroy();
        retries++;
        if (retries >= maxRetries) {
          reject(new Error(`Server not ready after ${maxRetries} retries (timeout)`));
        } else {
          console.log(`Waiting for server... (${retries}/${maxRetries})`);
          setTimeout(checkServer, 1000);
        }
      });

      req.end();
    };

    checkServer();
  });
}

// Main execution
async function main() {
  try {
    console.log('='.repeat(60));
    console.log('Testing /health endpoint with Content-Length validation fix');
    console.log('='.repeat(60));

    // Wait for server to be ready
    console.log('Checking if backend server is running...');
    await waitForServer();

    // Test the health endpoint
    const result = await testHealthEndpoint();

    console.log('\n' + '='.repeat(60));
    if (result.success) {
      console.log('🎉 TEST PASSED: Content-Length validation fix is working');
      console.log('The /health endpoint now accepts GET requests without Content-Length header');
    } else {
      console.log('💥 TEST FAILED: Content-Length validation fix did not work');
      process.exit(1);
    }
    console.log('='.repeat(60));

  } catch (error) {
    console.error('Test execution failed:', error.message);
    process.exit(1);
  }
}

// Run the test
if (require.main === module) {
  main();
}

module.exports = { testHealthEndpoint };