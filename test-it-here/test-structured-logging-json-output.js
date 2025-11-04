const { logger } = require('../shared/dist/shared/src/utils/logger.js');

// Mock console methods to capture output
const originalConsole = {
  log: console.log,
  info: console.info,
  warn: console.warn,
  error: console.error,
  debug: console.debug
};
let capturedOutput = null;

const captureConsole = (message) => {
  capturedOutput = message;
  originalConsole.log(message); // Also log to console for debugging
};

console.log = captureConsole;
console.info = captureConsole;
console.warn = captureConsole;
console.error = captureConsole;
console.debug = captureConsole;

function testLoggerOutputsJSON() {
  console.log('Testing logger JSON output...');

  // Test info level with meta
  capturedOutput = null;
  logger.info('Test message', { userId: '12345', action: 'verify' });

  console.log('Captured output:', typeof capturedOutput, capturedOutput);
  if (!capturedOutput) {
    throw new Error('Logger did not output anything');
  }

  // Parse the JSON output
  let parsedLog;
  try {
    parsedLog = JSON.parse(capturedOutput);
  } catch (e) {
    throw new Error(`Logger output is not valid JSON: ${capturedOutput}`);
  }

  // Check required fields
  if (!parsedLog.timestamp) {
    throw new Error('Log object missing timestamp field');
  }
  if (typeof parsedLog.timestamp !== 'string') {
    throw new Error('Timestamp must be a string');
  }
  // Check if timestamp is ISO 8601 format (basic check)
  if (!parsedLog.timestamp.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/)) {
    throw new Error('Timestamp is not in ISO 8601 format');
  }

  if (parsedLog.level !== 'INFO') {
    throw new Error(`Expected level 'INFO', got '${parsedLog.level}'`);
  }

  if (parsedLog.message !== 'Test message') {
    throw new Error(`Expected message 'Test message', got '${parsedLog.message}'`);
  }

  // Check meta fields are included
  if (parsedLog.userId !== '12345') {
    throw new Error(`Expected userId '12345', got '${parsedLog.userId}'`);
  }
  if (parsedLog.action !== 'verify') {
    throw new Error(`Expected action 'verify', got '${parsedLog.action}'`);
  }

  console.log('✓ INFO level with meta passed');

  // Test error level without meta
  capturedOutput = null;
  logger.error('Error message');

  if (!capturedOutput) {
    throw new Error('Logger did not output anything for error');
  }

  try {
    parsedLog = JSON.parse(capturedOutput);
  } catch (e) {
    throw new Error(`Logger output is not valid JSON: ${capturedOutput}`);
  }

  // Check that sanitized is present
  if (parsedLog.sanitized !== true) {
    throw new Error(`Expected sanitized to be true, got '${parsedLog.sanitized}'`);
  }

  console.log('✓ INFO level with meta passed');

  if (parsedLog.level !== 'ERROR') {
    throw new Error(`Expected level 'ERROR', got '${parsedLog.level}'`);
  }

  if (parsedLog.message !== 'Error message') {
    throw new Error(`Expected message 'Error message', got '${parsedLog.message}'`);
  }

  // Ensure no extra meta fields
  if (parsedLog.userId !== undefined) {
    throw new Error('Unexpected userId field in log without meta');
  }

  console.log('✓ ERROR level without meta passed');

  // Test warn level with empty meta
  capturedOutput = null;
  logger.warn('Warn message', {});

  if (!capturedOutput) {
    throw new Error('Logger did not output anything for warn');
  }

  try {
    parsedLog = JSON.parse(capturedOutput);
  } catch (e) {
    throw new Error(`Logger output is not valid JSON: ${capturedOutput}`);
  }

  if (parsedLog.level !== 'WARN') {
    throw new Error(`Expected level 'WARN', got '${parsedLog.level}'`);
  }

  if (parsedLog.message !== 'Warn message') {
    throw new Error(`Expected message 'Warn message', got '${parsedLog.message}'`);
  }

  console.log('✓ WARN level with empty meta passed');

  console.log('All tests passed!');
}

// Run the test
try {
  testLoggerOutputsJSON();
} catch (error) {
  console.error('Test failed:', error.message);
  process.exit(1);
} finally {
  // Restore original console methods
  console.log = originalConsole.log;
  console.info = originalConsole.info;
  console.warn = originalConsole.warn;
  console.error = originalConsole.error;
  console.debug = originalConsole.debug;
}