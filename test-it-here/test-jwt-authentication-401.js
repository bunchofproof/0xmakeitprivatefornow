const http = require('http');

console.log('Testing JWT Authentication Implementation');
console.log('=======================================');

// Test configuration
const TEST_HOST = 'localhost';
const TEST_PORT = 3001;
const BASE_URL = `http://${TEST_HOST}:${TEST_PORT}/api/admin/stats`;

// Helper function to make HTTP requests
function makeRequest(options, data = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => body += chunk);
      res.on('end', () => {
        try {
          const parsed = body ? JSON.parse(body) : {};
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: parsed
          });
        } catch (e) {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: body
          });
        }
      });
    });

    req.on('error', reject);

    if (data) {
      req.write(JSON.stringify(data));
    }

    req.end();
  });
}

// Test cases
async function runTests() {
  console.log('\n1. Testing request without Authorization header...');

  try {
    const response = await makeRequest({
      hostname: TEST_HOST,
      port: TEST_PORT,
      path: '/api/admin/stats',
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    });

    console.log(`Status: ${response.status}`);
    console.log(`Response: ${JSON.stringify(response.body, null, 2)}`);

    if (response.status === 401) {
      console.log('✅ PASS: Request without Authorization header correctly returns 401');
    } else {
      console.log('❌ FAIL: Expected 401, got', response.status);
      return false;
    }
  } catch (error) {
    console.log('❌ FAIL: Request failed with error:', error.message);
    return false;
  }

  console.log('\n2. Testing request with invalid JWT token...');

  try {
    const response = await makeRequest({
      hostname: TEST_HOST,
      port: TEST_PORT,
      path: '/api/admin/stats',
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer invalid.jwt.token'
      }
    });

    console.log(`Status: ${response.status}`);
    console.log(`Response: ${JSON.stringify(response.body, null, 2)}`);

    if (response.status === 401) {
      console.log('✅ PASS: Request with invalid JWT correctly returns 401');
    } else {
      console.log('❌ FAIL: Expected 401, got', response.status);
      return false;
    }
  } catch (error) {
    console.log('❌ FAIL: Request failed with error:', error.message);
    return false;
  }

  console.log('\n3. Testing request with expired JWT token (if available)...');
  // Note: We can't easily test expired tokens without knowing the secret
  // This would require generating a token and waiting, or mocking time
  console.log('⚠️  SKIP: Cannot test expired tokens without token generation');

  console.log('\n4. Testing request with valid JWT token...');
  // This will fail until we implement proper JWT generation and authentication

  try {
    // For now, we'll test with a placeholder - this should fail
    const response = await makeRequest({
      hostname: TEST_HOST,
      port: TEST_PORT,
      path: '/api/admin/stats',
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer valid.jwt.token.placeholder'
      }
    });

    console.log(`Status: ${response.status}`);
    console.log(`Response: ${JSON.stringify(response.body, null, 2)}`);

    if (response.status === 401) {
      console.log('✅ PASS: Request with placeholder JWT correctly returns 401 (no valid token yet)');
    } else if (response.status >= 200 && response.status < 300) {
      console.log('❌ FAIL: Got successful response, but expected 401 (authentication not implemented yet)');
      return false;
    } else {
      console.log('❌ FAIL: Unexpected status code:', response.status);
      return false;
    }
  } catch (error) {
    console.log('❌ FAIL: Request failed with error:', error.message);
    return false;
  }

  console.log('\n✅ All tests passed! JWT authentication is properly rejecting unauthorized requests.');
  return true;
}

// Check if server is running
console.log('\nChecking if backend server is running...');
makeRequest({
  hostname: TEST_HOST,
  port: TEST_PORT,
  path: '/health',
  method: 'GET'
}).then(() => {
  console.log('✅ Server is running, proceeding with tests...\n');
  return runTests();
}).then((success) => {
  if (success) {
    console.log('\n🎉 All JWT authentication tests passed!');
    process.exit(0);
  } else {
    console.log('\n💥 Some tests failed!');
    process.exit(1);
  }
}).catch((error) => {
  console.log('❌ Server is not running or health check failed:', error.message);
  console.log('Please start the backend server first: cd zk-discord-verifier/backend && npm start');
  process.exit(1);
});