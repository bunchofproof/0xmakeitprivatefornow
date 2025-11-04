/**
 * Security Headers Validation Script
 * Tests all implemented security headers across different environments
 */

const http = require('http');

/**
 * Security headers validation configuration
 */
const SECURITY_HEADERS = {
  // Core Security Headers
  'X-Content-Type-Options': { required: true, value: 'nosniff' },
  'X-Frame-Options': { required: true, value: 'DENY' },
  'X-XSS-Protection': { required: true, contains: '1; mode=block' },
  'Referrer-Policy': { required: true, value: 'strict-origin-when-cross-origin' },
  
  // Additional Security Headers
  'X-Permitted-Cross-Domain-Policies': { required: true, value: 'none' },
  'X-Download-Options': { required: true, value: 'noopen' },
  'X-DNS-Prefetch-Control': { required: true, value: 'off' },
  
  // Cross-Origin Security Headers
  'Cross-Origin-Opener-Policy': { required: true },
  'Cross-Origin-Embedder-Policy': { required: true, value: 'require-corp' },
  'Cross-Origin-Resource-Policy': { required: true, value: 'same-origin' },
  
  // Content Security Policy
  'Content-Security-Policy': { required: true, contains: "default-src 'self'" },
  
  // Permissions Policy
  'Permissions-Policy': { required: true, contains: 'camera=()' },
  
  // Reporting Headers
  'Reporting-Endpoints': { required: true },
  
  // Transport Security (Production Only)
  'Strict-Transport-Security': { required: false, productionOnly: true },
  'Expect-CT': { required: false, productionOnly: true }
};

/**
 * Test security headers for a given URL
 */
async function testSecurityHeaders(url, environment = 'development') {
  console.log(`\n🔍 Testing Security Headers for: ${url}`);
  console.log(`Environment: ${environment}`);
  console.log('='.repeat(60));
  
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      let data = '';
      let passedTests = 0;
      let failedTests = 0;
      const errors = [];
      
      console.log('\n📊 Security Headers Analysis:');
      console.log('-'.repeat(40));
      
      // Test each security header
      Object.entries(SECURITY_HEADERS).forEach(([headerName, config]) => {
        const headerValue = res.headers[headerName.toLowerCase()];
        const isProductionOnly = config.productionOnly;
        const shouldTest = !isProductionOnly || environment === 'production';
        
        if (!shouldTest) {
          console.log(`⏭️  ${headerName}: Skipped (production only)`);
          return;
        }
        
        if (!headerValue) {
          if (config.required) {
            console.log(`❌ ${headerName}: MISSING`);
            failedTests++;
            errors.push(`${headerName}: Required header missing`);
          } else {
            console.log(`⚠️  ${headerName}: Not present (optional)`);
          }
          return;
        }
        
        // Validate header value
        let valid = true;
        if (config.value && headerValue !== config.value) {
          valid = false;
          errors.push(`${headerName}: Expected "${config.value}", got "${headerValue}"`);
        }
        
        if (config.contains && !headerValue.includes(config.contains)) {
          valid = false;
          errors.push(`${headerName}: Should contain "${config.contains}"`);
        }
        
        if (valid) {
          console.log(`✅ ${headerName}: ${headerValue}`);
          passedTests++;
        } else {
          console.log(`❌ ${headerName}: ${headerValue}`);
          failedTests++;
        }
      });
      
      // Check for additional security indicators
      console.log('\n🔒 Additional Security Checks:');
      console.log('-'.repeat(30));
      
      // Check for server information leakage
      if (res.headers.server) {
        console.log(`⚠️  Server header exposed: ${res.headers.server}`);
        failedTests++;
      } else {
        console.log('✅ Server header properly hidden');
        passedTests++;
      }
      
      // Check content security policy quality
      const csp = res.headers['content-security-policy'];
      if (csp) {
        const cspTests = {
          'XSS Protection': csp.includes('upgrade-insecure-requests'),
          'Mixed Content Blocking': csp.includes('block-all-mixed-content'),
          'Frame Protection': csp.includes("frame-ancestors 'none'"),
          'Script Protection': csp.includes("script-src 'self'"),
          'Object Blocking': csp.includes("object-src 'none'")
        };
        
        Object.entries(cspTests).forEach(([test, passed]) => {
          if (passed) {
            console.log(`✅ CSP ${test}: Implemented`);
            passedTests++;
          } else {
            console.log(`❌ CSP ${test}: Missing`);
            failedTests++;
          }
        });
      }
      
      // Summary
      console.log('\n📈 Test Summary:');
      console.log('-'.repeat(20));
      console.log(`✅ Passed: ${passedTests}`);
      console.log(`❌ Failed: ${failedTests}`);
      console.log(`📊 Success Rate: ${((passedTests / (passedTests + failedTests)) * 100).toFixed(1)}%`);
      
      if (errors.length > 0) {
        console.log('\n⚠️  Issues Found:');
        errors.forEach(error => console.log(`  • ${error}`));
      }
      
      const overallScore = (passedTests / (passedTests + failedTests)) * 100;
      const grade = overallScore >= 95 ? 'A+' : 
                   overallScore >= 90 ? 'A' :
                   overallScore >= 80 ? 'B' :
                   overallScore >= 70 ? 'C' : 'D';
      
      console.log(`\n🏆 Security Grade: ${grade} (${overallScore.toFixed(1)}%)`);
      
      if (overallScore >= 90) {
        console.log('🎉 Excellent security posture!');
      } else if (overallScore >= 80) {
        console.log('👍 Good security, with room for improvement');
      } else {
        console.log('⚠️  Security needs significant improvement');
      }
      
      resolve({
        passed: passedTests,
        failed: failedTests,
        score: overallScore,
        grade: grade,
        errors: errors
      });
      
    });
    
    req.on('error', (error) => {
      console.error(`❌ Error testing ${url}:`, error.message);
      reject(error);
    });
    
    req.setTimeout(10000, () => {
      console.error(`❌ Timeout testing ${url}`);
      reject(new Error('Request timeout'));
    });
  });
}

/**
 * Test multiple endpoints
 */
async function testAllEndpoints() {
  const baseUrl = process.env.BASE_URL || 'http://localhost:3001';
  const environment = process.env.NODE_ENV || 'development';
  
  console.log('🚀 Starting Security Headers Validation');
  console.log('========================================');
  console.log(`Base URL: ${baseUrl}`);
  console.log(`Environment: ${environment}`);
  
  const endpoints = [
    { path: '/health', name: 'Health Check' },
    { path: '/api/verify/status', name: 'Verify API' },
    { path: '/api/admin/stats', name: 'Admin API' }
  ];
  
  const results = [];
  
  for (const endpoint of endpoints) {
    try {
      const url = `${baseUrl}${endpoint.path}`;
      const result = await testSecurityHeaders(url, environment);
      results.push({
        endpoint: endpoint.name,
        url: endpoint.path,
        ...result
      });
    } catch (error) {
      console.error(`❌ Failed to test ${endpoint.name}:`, error.message);
      results.push({
        endpoint: endpoint.name,
        url: endpoint.path,
        error: error.message
      });
    }
  }
  
  // Overall summary
  console.log('\n🎯 Overall Security Assessment');
  console.log('==============================');
  
  const validResults = results.filter(r => !r.error);
  if (validResults.length === 0) {
    console.log('❌ No endpoints could be tested');
    return;
  }
  
  const avgScore = validResults.reduce((sum, r) => sum + r.score, 0) / validResults.length;
  const totalPassed = validResults.reduce((sum, r) => sum + r.passed, 0);
  const totalFailed = validResults.reduce((sum, r) => sum + r.failed, 0);
  
  console.log(`📊 Average Score: ${avgScore.toFixed(1)}%`);
  console.log(`✅ Total Passed: ${totalPassed}`);
  console.log(`❌ Total Failed: ${totalFailed}`);
  console.log(`🏆 Overall Grade: ${avgScore >= 95 ? 'A+' : avgScore >= 90 ? 'A' : avgScore >= 80 ? 'B' : avgScore >= 70 ? 'C' : 'D'}`);
  
  if (avgScore >= 90) {
    console.log('\n🎉 COMPREHENSIVE SECURITY HEADERS IMPLEMENTATION SUCCESSFUL!');
    console.log('🛡️ All services are protected against common web vulnerabilities.');
    console.log('✅ Defense-in-depth security posture achieved.');
  } else {
    console.log('\n⚠️  Security headers implementation needs attention.');
    console.log('📋 Review failed tests and implement missing security headers.');
  }
}

// Run tests if called directly
if (require.main === module) {
  testAllEndpoints().catch(error => {
    console.error('❌ Validation failed:', error);
    process.exit(1);
  });
}

module.exports = {
  testSecurityHeaders,
  testAllEndpoints,
  SECURITY_HEADERS
};