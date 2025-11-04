const http = require('http');

console.log('Testing CSP Policy Implementation');
console.log('===================================');

// Test configuration
const TEST_HOST = 'localhost';
const TEST_PORT = 3000;
const BASE_URL = `http://${TEST_HOST}:${TEST_PORT}/`;

// Helper function to make HTTP requests
function makeRequest(options, data = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => body += chunk);
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: body
        });
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
  console.log('\n1. Testing CSP header presence and content...');

  try {
    const response = await makeRequest({
      hostname: TEST_HOST,
      port: TEST_PORT,
      path: '/',
      method: 'GET',
      headers: {
        'Content-Type': 'text/html'
      }
    });

    console.log(`Status: ${response.status}`);
    console.log(`CSP Header: ${response.headers['content-security-policy'] || 'NOT PRESENT'}`);

    const csp = response.headers['content-security-policy'];

    if (!csp) {
      console.log('❌ FAIL: Content-Security-Policy header is missing');
      return false;
    }

    // Check that 'unsafe-inline' is NOT in style-src
    const styleSrcMatch = csp.match(/style-src\s+([^;]+)/);
    if (!styleSrcMatch) {
      console.log('❌ FAIL: style-src directive not found in CSP');
      return false;
    }

    const styleSrc = styleSrcMatch[1];
    if (styleSrc.includes("'unsafe-inline'")) {
      console.log('❌ FAIL: style-src contains \'unsafe-inline\' - vulnerability not remediated');
      console.log(`Found in: ${styleSrc}`);
      return false;
    } else {
      console.log('✅ PASS: style-src does not contain \'unsafe-inline\'');
    }

    // Check that nonce is present in both style-src and script-src
    const noncePattern = /'nonce-[a-zA-Z0-9+/=]{32,}'/;
    const nonceMatches = csp.match(noncePattern);

    if (!nonceMatches || nonceMatches.length < 2) {
      console.log('❌ FAIL: Expected at least 2 nonce values (for script-src and style-src)');
      console.log(`Found: ${nonceMatches ? nonceMatches.length : 0} nonce(s)`);
      return false;
    }

    console.log('✅ PASS: Found nonce values in CSP');
    console.log(`Nonces: ${nonceMatches.join(', ')}`);

    // Check that nonce is in both script-src and style-src
    const scriptSrcMatch = csp.match(/script-src\s+([^;]+)/);
    const styleSrcMatchAgain = csp.match(/style-src\s+([^;]+)/);

    let scriptNoncePresent = false;
    let styleNoncePresent = false;

    if (scriptSrcMatch && scriptSrcMatch[1].match(noncePattern)) {
      scriptNoncePresent = true;
      console.log('✅ PASS: script-src contains nonce');
    } else {
      console.log('❌ FAIL: script-src does not contain nonce');
    }

    if (styleSrcMatchAgain && styleSrcMatchAgain[1].match(noncePattern)) {
      styleNoncePresent = true;
      console.log('✅ PASS: style-src contains nonce');
    } else {
      console.log('❌ FAIL: style-src does not contain nonce');
    }

    if (!scriptNoncePresent || !styleNoncePresent) {
      return false;
    }

    console.log('\n✅ All CSP policy tests passed!');
    return true;

  } catch (error) {
    console.log('❌ FAIL: Request failed with error:', error.message);
    return false;
  }
}

// Check if server is running
console.log('\nChecking if web server is running...');
makeRequest({
  hostname: TEST_HOST,
  port: TEST_PORT,
  path: '/',
  method: 'GET'
}).then(() => {
  console.log('✅ Server is running, proceeding with tests...\n');
  return runTests();
}).then((success) => {
  if (success) {
    console.log('\n🎉 CSP Policy test completed successfully!');
    console.log('The CSP header is correctly configured:');
    console.log('- style-src does not contain \'unsafe-inline\'');
    console.log('- nonce is present in both script-src and style-src');
    process.exit(0);
  } else {
    console.log('\n💥 CSP Policy test failed!');
    console.log('The CSP vulnerability has not been properly remediated.');
    process.exit(1);
  }
}).catch((error) => {
  console.log('❌ Server is not running or health check failed:', error.message);
  console.log('Please start the web server first: cd zk-discord-verifier/web && npm run dev');
  process.exit(1);
});