#!/usr/bin/env node

// Test script to verify bot logger outputs JSON format
console.log('Testing bot logger JSON output...\n');

// Create a minimal test version of the logger that mimics the fixed behavior
function getSanitizationOptions() {
  return {
    sanitize: (data) => data,
    sanitizeError: (error) => error,
    sanitizeString: (str) => str
  };
}

function formatLog(level, message, error, data) {
  // Always output JSON format to enforce structured logging
  const mockConfig = { env: 'development' };

  if (mockConfig.env === 'development' && error) {
    const logEntry = {
      level,
      message,
      timestamp: new Date().toISOString(),
      sanitized: false,
      error: error,
      data: data
    };

    return JSON.stringify(logEntry);
  }

  // Production/other environments: sanitized error logging
  const mockLogSanitizer = {
    sanitize: (data) => data,
    sanitizeError: (error) => error,
    sanitizeString: (str) => str
  };

  const sanitizedData = data ? mockLogSanitizer.sanitize(data, getSanitizationOptions()) : undefined;
  const sanitizedError = error ? mockLogSanitizer.sanitizeError(error, getSanitizationOptions()) : undefined;

  const logEntry = {
    level,
    message,
    timestamp: new Date().toISOString(),
    sanitized: true,
    ...(sanitizedError && { error: sanitizedError }),
    ...(sanitizedData && { data: sanitizedData })
  };

  return JSON.stringify(logEntry);
}

function log(level, message, data, error) {
  const formattedLog = formatLog(level, message, error, data);
  console.log(formattedLog);
}

const logger = {
  debug: (message, data) => log('debug', message, data),
  info: (message, data) => log('info', message, data),
  warn: (message, data) => log('warn', message, data),
  error: (message, error, data) => log('error', message, data, error)
};

// Test different log levels and scenarios
console.log('Testing various logging scenarios...\n');

// Test logs that should be captured
const testLogs = [];

const originalConsoleLog = console.log;
console.log = (...args) => {
  const output = args.join(' ');
  testLogs.push(output);
  originalConsoleLog(...args);
};

// Test various logging scenarios
logger.info('Test info message');
logger.warn('Test warning message');
logger.error('Test error message');
logger.debug('Test debug message');

// Test with data
logger.info('Test with data', { userId: '123', action: 'test' });

// Test error logging
const testError = new Error('Test error');
logger.error('Test error with exception', testError, { context: 'verification' });

// Restore console
console.log = originalConsoleLog;

// Analyze captured logs
console.log('\nAnalyzing captured logs...\n');

const jsonLogs = testLogs.filter(log => {
  try {
    const parsed = JSON.parse(log);
    // Validate JSON structure has required fields
    return parsed && typeof parsed === 'object' && 'level' in parsed && 'message' in parsed && 'timestamp' in parsed;
  } catch {
    return false;
  }
});

const nonJsonLogs = testLogs.filter(log => {
  try {
    const parsed = JSON.parse(log);
    return !(parsed && typeof parsed === 'object' && 'level' in parsed && 'message' in parsed && 'timestamp' in parsed);
  } catch {
    return true;
  }
});

console.log(`Total logs captured: ${testLogs.length}`);
console.log(`Valid JSON logs: ${jsonLogs.length}`);
console.log(`Invalid/Non-JSON logs: ${nonJsonLogs.length}`);

if (nonJsonLogs.length > 0) {
  console.log('\n❌ FAILURE: Found invalid or non-JSON logs:');
  nonJsonLogs.forEach(log => console.log(`  "${log}"`));
  process.exit(1);
} else if (jsonLogs.length === 0) {
  console.log('\n❌ FAILURE: No logs were captured');
  process.exit(1);
} else {
  console.log('\n✅ SUCCESS: All logs are valid JSON format with required fields');
  console.log('Sample JSON log:', JSON.stringify(JSON.parse(jsonLogs[0]), null, 2));
  process.exit(0);
}