const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

// Original console methods
const originalConsole = {
  log: console.log,
  info: console.info,
  warn: console.warn,
  error: console.error,
  debug: console.debug
};

// Capture all console output
let allCapturedLogs = [];
let captureEnabled = false;

function captureConsole(level) {
  return function(...args) {
    const message = args.join(' ');
    if (captureEnabled) {
      allCapturedLogs.push({ level, message, timestamp: Date.now() });
    }
    // Still log to original console for debugging
    originalConsole[level].apply(console, args);
  };
}

// Override console methods
console.log = captureConsole('log');
console.info = captureConsole('info');
console.warn = captureConsole('warn');
console.error = captureConsole('error');
console.debug = captureConsole('debug');

function validateStructuredLogging() {
  console.log('Starting structured logging validation for bot project...\n');

  // Enable capture
  captureEnabled = true;
  allCapturedLogs = [];

  return new Promise((resolve, reject) => {
    // Run TypeScript compilation to check for errors
    const compileCmd = 'cd zk-discord-verifier/bot && npx tsc --noEmit';
    console.log('Compiling bot project...');

    exec(compileCmd, { cwd: path.join(__dirname, '..') }, (error, stdout, stderr) => {
      if (error) {
        console.error('Compilation failed:', error.message);
        console.error('stdout:', stdout);
        console.error('stderr:', stderr);
        resolve(false);
        return;
      }

      console.log('✓ Compilation successful');

      // Now test by importing a module that uses logging
      console.log('Testing logger calls...');

      try {
        // Import a module that uses logging to trigger the calls
        const tokenGenerator = require('../bot/src/utils/tokenGenerator.js');

        // Call a function that logs
        tokenGenerator.generateVerificationToken('test-user', 'test-session');

        // Check captured logs
        const jsonLogs = allCapturedLogs.filter(log => {
          try {
            JSON.parse(log.message);
            return true;
          } catch {
            return false;
          }
        });

        if (jsonLogs.length === 0) {
          console.error('No JSON logs found. Logger calls may not be using structured format.');
          resolve(false);
          return;
        }

        console.log(`✓ Found ${jsonLogs.length} JSON-formatted logs`);

        // Validate log structure
        let validLogs = 0;
        for (const log of jsonLogs) {
          try {
            const parsed = JSON.parse(log.message);

            // Check required fields
            if (!parsed.timestamp || !parsed.level || !parsed.message) {
              console.error('Invalid log structure:', log.message);
              continue;
            }

            // Check timestamp format
            if (!parsed.timestamp.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/)) {
              console.error('Invalid timestamp format:', parsed.timestamp);
              continue;
            }

            validLogs++;
          } catch (e) {
            console.error('Failed to parse log:', log.message);
          }
        }

        if (validLogs > 0) {
          console.log(`✓ ${validLogs} logs have valid structured format`);
          console.log('✓ Structured logging validation passed');
          resolve(true);
        } else {
          console.log('✗ No valid structured logs found');
          resolve(false);
        }

      } catch (importError) {
        console.error('Failed to import module:', importError.message);
        resolve(false);
      }
    });
  });
}

// Run the test
validateStructuredLogging().then(success => {
  // Restore original console
  console.log = originalConsole.log;
  console.info = originalConsole.info;
  console.warn = originalConsole.warn;
  console.error = originalConsole.error;
  console.debug = originalConsole.debug;

  if (success) {
    console.log('\n🎉 Bot structured logging validation PASSED');
    process.exit(0);
  } else {
    console.log('\n❌ Bot structured logging validation FAILED');
    process.exit(1);
  }
}).catch(error => {
  console.error('Test execution failed:', error);
  process.exit(1);
});