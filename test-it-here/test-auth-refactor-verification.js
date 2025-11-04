#!/usr/bin/env node

/**
 * Verification script for auth.ts refactoring
 * Tests that the refactored modules work correctly and maintain backward compatibility
 */

const path = require('path');

// Setup environment
process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test_db';

// Import required modules
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Simple mock implementation instead of jest
const createMock = () => {
  const mock = function() {
    const call = mock.mock.calls[mock.mock.calls.length - 1];
    if (call && call.length > 0) {
      return call[0];
    }
    return undefined;
  };
  mock.mock = { calls: [] };
  mock.mockResolvedValue = (value) => {
    mock.mock.result = value;
    return mock;
  };
  mock.mockReturnValue = (value) => {
    mock.mock.result = value;
    return mock;
  };
  mock.mockReturnThis = () => {
    mock.mock.result = mock;
    return mock;
  };
  return mock;
};

// Mock database and config
const mockPrisma = {
  verificationSession: {
    findUnique: createMock(),
    create: createMock(),
    update: createMock(),
  },
  adminVerification: {
    findUnique: createMock(),
  }
};

const mockConfig = {
  security: {
    jwtSecret: 'test-jwt-secret-for-verification'
  }
};

const mockLogger = {
  warn: createMock(),
  error: createMock(),
  info: createMock()
};

const mockAuditLogger = {
  logSecurityEvent: createMock()
};

// Override require to mock dependencies
const Module = require('module');
const originalRequire = Module.prototype.require;

Module.prototype.require = function(id) {
  if (id === '../backend/src/utils/database') {
    return { prisma: mockPrisma };
  }
  if (id === '../backend/src/config') {
    return { config: mockConfig };
  }
  if (id === '../backend/src/utils/logger') {
    return { logger: mockLogger };
  }
  if (id === '@shared/services/auditLogger') {
    return { auditLogger: mockAuditLogger };
  }
  return originalRequire.apply(this, arguments);
};

// Import the refactored modules (with error handling)
let validateApiKey, validateToken, requireValidToken, checkVerificationStatus;

try {
  const tokenAuth = require('../backend/src/middleware/tokenAuth');
  const sessionAuth = require('../backend/src/middleware/sessionAuth');
  validateApiKey = tokenAuth.validateApiKey;
  validateToken = sessionAuth.validateToken;
  requireValidToken = sessionAuth.requireValidToken;
  checkVerificationStatus = sessionAuth.checkVerificationStatus;
} catch (error) {
  console.error('Failed to load modules:', error.message);
  process.exit(1);
}

console.log('Starting Auth Refactoring Verification Tests...\n');

// Simple test runner
const tests = [];
const results = { passed: 0, failed: 0 };

function test(name, fn) {
  tests.push({ name, fn });
}

function runTests() {
  tests.forEach(({ name, fn }) => {
    try {
      fn();
      console.log(`✅ PASS: ${name}`);
      results.passed++;
    } catch (error) {
      console.log(`❌ FAIL: ${name} - ${error.message}`);
      results.failed++;
    }
  });

  console.log(`\nTest Results: ${results.passed} passed, ${results.failed} failed`);
  if (results.failed === 0) {
    console.log('🎉 All tests passed! Refactoring verification successful.');
    process.exit(0);
  } else {
    console.log('💥 Some tests failed. Refactoring needs attention.');
    process.exit(1);
  }
}

// Setup mocks for each test
function setupMocks() {
  // Reset mocks
  mockPrisma.verificationSession.findUnique.mock.calls.length = 0;
  mockPrisma.adminVerification.findUnique.mock.calls.length = 0;
  mockLogger.warn.mock.calls.length = 0;
  mockLogger.error.mock.calls.length = 0;
  mockAuditLogger.logSecurityEvent.mock.calls.length = 0;
}

// Test cases
test('validateApiKey should validate valid JWT token', () => {
  setupMocks();

  const mockReq = {
    headers: { authorization: 'Bearer valid-jwt-token' },
    ip: '127.0.0.1'
  };
  const mockRes = {
    status: createMock(),
    json: createMock()
  };
  const mockNext = createMock();

  // Mock jwt.verify to return decoded token
  jwt.verify = () => ({
    userId: 'test-user-id',
    sessionId: 'test-session-id',
    sub: 'test-sub'
  });

  validateApiKey(mockReq, mockRes, mockNext);

  if (mockNext.mock.calls.length !== 1) {
    throw new Error('next() should have been called');
  }
  if (mockReq.userId !== 'test-user-id') {
    throw new Error('userId should be set on request');
  }
  if (mockReq.sessionId !== 'test-session-id') {
    throw new Error('sessionId should be set on request');
  }
});

test('validateApiKey should reject missing authorization header', () => {
  setupMocks();

  const mockReq = { headers: {}, ip: '127.0.0.1' };
  const mockRes = {
    status: createMock(),
    json: createMock()
  };
  const mockNext = createMock();

  validateApiKey(mockReq, mockRes, mockNext);

  if (mockRes.status.mock.calls[0][0] !== 401) {
    throw new Error('Should return 401 status');
  }
  if (mockNext.mock.calls.length !== 0) {
    throw new Error('next() should not have been called');
  }
});

test('validateToken should validate valid session token', async () => {
  setupMocks();

  const futureDate = new Date(Date.now() + 3600000);
  mockPrisma.verificationSession.findUnique.mockResolvedValue({
    id: 'test-session-id',
    discordUserId: 'test-discord-user',
    expiresAt: futureDate,
    used: false
  });

  const result = await validateToken('test-session-id');

  if (!result.valid) {
    throw new Error('Token should be valid');
  }
  if (result.sessionId !== 'test-session-id') {
    throw new Error('Session ID should match');
  }
});

test('validateToken should reject expired session', async () => {
  setupMocks();

  const pastDate = new Date(Date.now() - 3600000);
  mockPrisma.verificationSession.findUnique.mockResolvedValue({
    id: 'test-session-id',
    discordUserId: 'test-discord-user',
    expiresAt: pastDate,
    used: false
  });

  const result = await validateToken('test-session-id');

  if (result.valid) {
    throw new Error('Expired token should be invalid');
  }
  if (result.message !== 'Session expired') {
    throw new Error('Should return expired message');
  }
});

test('requireValidToken should accept valid token', async () => {
  setupMocks();

  const futureDate = new Date(Date.now() + 3600000);
  mockPrisma.verificationSession.findUnique.mockResolvedValue({
    id: 'test-session-id',
    discordUserId: 'test-discord-user',
    expiresAt: futureDate,
    used: false
  });

  const mockReq = { body: { token: 'test-session-id' }, ip: '127.0.0.1' };
  const mockRes = {
    status: createMock(),
    json: createMock()
  };
  const mockNext = createMock();

  await requireValidToken(mockReq, mockRes, mockNext);

  if (mockNext.mock.calls.length !== 1) {
    throw new Error('next() should have been called');
  }
  if (mockReq.sessionId !== 'test-session-id') {
    throw new Error('sessionId should be set');
  }
});

test('checkVerificationStatus should allow new user', async () => {
  setupMocks();

  mockPrisma.adminVerification.findUnique.mockResolvedValue(null);

  const mockReq = { discordUserId: 'test-discord-user' };
  const mockRes = {
    status: createMock(),
    json: createMock()
  };
  const mockNext = createMock();

  await checkVerificationStatus(mockReq, mockRes, mockNext);

  if (mockNext.mock.calls.length !== 1) {
    throw new Error('next() should have been called for new user');
  }
});

test('Backward Compatibility - auth.ts exports', () => {
  try {
    const auth = require('../backend/src/middleware/auth');

    if (typeof auth.validateApiKey !== 'function') {
      throw new Error('validateApiKey should be exported');
    }
    if (typeof auth.validateToken !== 'function') {
      throw new Error('validateToken should be exported');
    }
    if (typeof auth.requireValidToken !== 'function') {
      throw new Error('requireValidToken should be exported');
    }
    if (typeof auth.checkVerificationStatus !== 'function') {
      throw new Error('checkVerificationStatus should be exported');
    }
  } catch (error) {
    throw new Error('Failed to load auth module: ' + error.message);
  }
});

test('Module Separation - functions in correct modules', () => {
  const tokenAuth = require('../backend/src/middleware/tokenAuth');
  const sessionAuth = require('../backend/src/middleware/sessionAuth');

  // tokenAuth should have JWT-related functions
  if (typeof tokenAuth.validateApiKey !== 'function') {
    throw new Error('validateApiKey should be in tokenAuth');
  }

  // sessionAuth should have session-related functions
  if (typeof sessionAuth.validateToken !== 'function') {
    throw new Error('validateToken should be in sessionAuth');
  }
  if (typeof sessionAuth.requireValidToken !== 'function') {
    throw new Error('requireValidToken should be in sessionAuth');
  }
  if (typeof sessionAuth.checkVerificationStatus !== 'function') {
    throw new Error('checkVerificationStatus should be in sessionAuth');
  }

  // Functions should not be duplicated between modules
  if (tokenAuth.validateToken !== undefined) {
    throw new Error('validateToken should not be in tokenAuth');
  }
  if (sessionAuth.validateApiKey !== undefined) {
    throw new Error('validateApiKey should not be in sessionAuth');
  }
});

// Run all tests
runTests();