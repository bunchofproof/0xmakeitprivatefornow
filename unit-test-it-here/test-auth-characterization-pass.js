const { exec } = require('child_process');
const path = require('path');

console.log('Testing auth characterization test suite...');

// Run the test from the unit-test-it-here directory
const testCommand = 'cd zk-discord-verifier && npx jest unit-test-it-here/auth.test.ts --verbose --forceExit';

exec(testCommand, (error, stdout, stderr) => {
  console.log('STDOUT:', stdout);
  if (stderr) {
    console.log('STDERR:', stderr);
  }

  if (error) {
    console.error('Test execution failed:', error);
    process.exit(1);
  }

  // Check if tests passed
  const passedTests = stdout.match(/Tests:\s+(\d+)\s+passed/);
  const failedTests = stdout.match(/Tests:\s+(\d+)\s+failed/);
  const totalTests = stdout.match(/Tests:\s+(\d+)\s+total/);

  if (passedTests && failedTests && totalTests) {
    const passed = parseInt(passedTests[1]);
    const failed = parseInt(failedTests[1]);
    const total = parseInt(totalTests[1]);

    console.log(`Test Results: ${passed} passed, ${failed} failed, ${total} total`);

    if (failed === 0 && total > 0) {
      console.log('✅ SUCCESS: All auth characterization tests passed!');
      process.exit(0);
    } else {
      console.log('❌ FAILURE: Some tests failed');
      process.exit(1);
    }
  } else {
    console.log('Could not parse test results');
    process.exit(1);
  }
});