const { exec } = require('child_process');
const path = require('path');

console.log('Running auth characterization test with fixes...');

const testCommand = 'npx jest --testPathPatterns=unit-test-it-here/auth.test.ts --verbose';

exec(testCommand, { cwd: path.join(__dirname, '..') }, (error, stdout, stderr) => {
  if (error) {
    console.error(`Test execution failed: ${error.message}`);
    process.exit(1);
  }

  console.log('STDOUT:', stdout);
  if (stderr) {
    console.error('STDERR:', stderr);
  }

  // Check if tests passed
  if (stdout.includes('0 failed') && !stdout.includes('failed')) {
    console.log('✅ SUCCESS: All auth characterization tests are passing!');
    console.log('The Unit Test Safeguard is now 100% passing.');
  } else {
    console.log('❌ FAILURE: Tests are still failing.');
    console.log('Check the output above for details.');
    process.exit(1);
  }
});