import jwt from 'jsonwebtoken';
import Joi from 'joi';

// Mock dependencies
jest.mock('../backend/src/config', () => ({
  config: {
    security: {
      jwtSecret: 'test-jwt-secret'
    }
  }
}));

jest.mock('../backend/src/utils/logger', () => ({
  logger: {
    warn: jest.fn(),
    info: jest.fn(),
    error: jest.fn()
  }
}));

jest.mock('../backend/src/utils/database', () => ({
  prisma: {
    verificationSession: {
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn()
    },
    adminVerification: {
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn()
    }
  }
}));

// Mock auditLogger
jest.mock('@shared/services/auditLogger', () => ({
  auditLogger: {
    logSecurityEvent: jest.fn()
  }
}));

// Import after mocks are set up using require to avoid TypeScript issues
const {
  validateToken,
  validateApiKey,
  requireValidToken,
  checkVerificationStatus,
  checkVerificationRateLimit,
  cleanupRateLimitEntries,
  clearRateLimitMapForTesting,
  validateAndSanitize,
  validateParams,
  securityValidation,
  checkValidationRateLimit,
  cleanupValidationFailureEntries,
  clearValidationFailureMapForTesting,
  validateRequestSize,
  validateRequestHeaders,
  stopRateLimitCleanup,
  stopValidationFailureCleanup
} = require('../backend/src/middleware/auth');
const { logger } = require('../backend/src/utils/logger');
const { prisma } = require('../backend/src/utils/database');
const { auditLogger } = require('@shared/services/auditLogger');

describe('Auth Middleware Characterization Tests', () => {
  let mockReq: any;
  let mockRes: any;
  let mockNext: jest.MockedFunction<any>;

  beforeEach(() => {
    jest.clearAllMocks();
    // Clear rate limit maps for independent tests
    clearRateLimitMapForTesting();
    clearValidationFailureMapForTesting();

    mockReq = {
      get: jest.fn((header: string) => {
        if (header === 'User-Agent') return 'test-agent';
        if (header === 'Content-Type') return 'application/json';
        return undefined;
      })
    };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis()
    };
    mockNext = jest.fn();
  });

  beforeAll(() => {
    process.env.NODE_ENV = 'test';
    // Stop any automatic cleanup intervals from previous tests
    const { stopRateLimitCleanup, stopValidationFailureCleanup } = require('../backend/src/middleware/auth');
    stopRateLimitCleanup();
    stopValidationFailureCleanup();
  });

  afterAll(() => {
    jest.clearAllTimers();
    jest.clearAllMocks();
    // Import cleanup functions and call them
    const { stopRateLimitCleanup, stopValidationFailureCleanup } = require('../backend/src/middleware/auth');
    stopRateLimitCleanup();
    stopValidationFailureCleanup();
  });

  describe('validateToken', () => {
    it('should return valid result for existing session', async () => {
      const mockSession = {
        id: 'test-session-id',
        discordUserId: 'test-discord-id',
        expiresAt: new Date(Date.now() + 3600000), // 1 hour from now
        used: false
      };

      (prisma.verificationSession.findUnique as jest.Mock).mockResolvedValue(mockSession);

      const result = await validateToken('test-session-id');

      expect(result).toEqual({
        valid: true,
        sessionId: 'test-session-id',
        discordUserId: 'test-discord-id',
        expiresAt: mockSession.expiresAt
      });
      expect(prisma.verificationSession.findUnique).toHaveBeenCalledWith({
        where: { id: 'test-session-id' }
      });
    });

    it('should return invalid result for non-existent session', async () => {
      (prisma.verificationSession.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await validateToken('non-existent-session');

      expect(result).toEqual({
        valid: false,
        message: 'Session not found'
      });
      expect(logger.warn).toHaveBeenCalledWith(
        'Verification session not found',
        { token: 'non-existent-session'.substring(0, 8) + '...' }
      );
    });

    it('should return invalid result for expired session', async () => {
      const mockSession = {
        id: 'expired-session-id',
        discordUserId: 'test-discord-id',
        expiresAt: new Date(Date.now() - 3600000), // 1 hour ago
        used: false
      };

      (prisma.verificationSession.findUnique as jest.Mock).mockResolvedValue(mockSession);

      const result = await validateToken('expired-session-id');

      expect(result).toEqual({
        valid: false,
        message: 'Session expired'
      });
      expect(logger.info).toHaveBeenCalledWith(
        'Expired verification session accessed',
        {
          sessionId: 'expired-session-id',
          discordUserId: 'test-discord-id'
        }
      );
    });

    it('should return invalid result for already used session', async () => {
      const mockSession = {
        id: 'used-session-id',
        discordUserId: 'test-discord-id',
        expiresAt: new Date(Date.now() + 3600000),
        used: true
      };

      (prisma.verificationSession.findUnique as jest.Mock).mockResolvedValue(mockSession);

      const result = await validateToken('used-session-id');

      expect(result).toEqual({
        valid: false,
        message: 'Session already used'
      });
      expect(logger.info).toHaveBeenCalledWith(
        'Used verification session accessed',
        {
          sessionId: 'used-session-id',
          discordUserId: 'test-discord-id'
        }
      );
    });

    it('should return invalid result when token is empty', async () => {
      const result = await validateToken('');

      expect(result).toEqual({
        valid: false,
        message: 'Token is required'
      });
      expect(prisma.verificationSession.findUnique).not.toHaveBeenCalled();
    });

    it('should handle database errors gracefully', async () => {
      (prisma.verificationSession.findUnique as jest.Mock).mockRejectedValue(new Error('Database error'));

      const result = await validateToken('test-session-id');

      expect(result).toEqual({
        valid: false,
        message: 'Token validation failed'
      });
      expect(logger.error).toHaveBeenCalledWith('Token validation error:', expect.any(Error));
    });
  });

  describe('validateApiKey', () => {
    it('should validate valid JWT token successfully', () => {
      const token = jwt.sign({ userId: 'test-user', sessionId: 'test-session' }, 'test-jwt-secret');
      mockReq.headers = { authorization: `Bearer ${token}` };

      validateApiKey(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect((mockReq as any).userId).toBe('test-user');
      expect((mockReq as any).sessionId).toBe('test-session');
    });

    it('should reject request without authorization header', () => {
      mockReq.headers = {};

      validateApiKey(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Authorization required',
        message: 'Please provide a JWT token in the Authorization header using Bearer scheme'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject request with invalid authorization header format', () => {
      mockReq.headers = { authorization: 'InvalidFormat token123' };

      validateApiKey(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Authorization required',
        message: 'Please provide a JWT token in the Authorization header using Bearer scheme'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject expired JWT token', () => {
      const expiredToken = jwt.sign({ userId: 'test-user' }, 'test-jwt-secret', { expiresIn: '-1h' });
      mockReq.headers = { authorization: `Bearer ${expiredToken}` };
      mockReq.ip = '127.0.0.1';

      validateApiKey(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Token expired',
        message: 'The JWT token has expired'
      });
      expect(logger.warn).toHaveBeenCalledWith(
        'Invalid JWT token provided',
        {
          ip: '127.0.0.1',
          error: 'jwt expired'
        }
      );
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject invalid JWT token', () => {
      mockReq.headers = { authorization: 'Bearer invalid-token' };
      mockReq.ip = '127.0.0.1';

      validateApiKey(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Invalid token',
        message: 'The JWT token is invalid'
      });
      expect(logger.warn).toHaveBeenCalledWith(
        'Invalid JWT token provided',
        {
          ip: '127.0.0.1',
          error: expect.any(String)
        }
      );
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('requireValidToken', () => {
    it('should proceed with valid token in body', async () => {
      const mockSession = {
        id: 'test-session-id',
        discordUserId: 'test-discord-id',
        expiresAt: new Date(Date.now() + 3600000),
        used: false
      };

      mockReq.body = { token: 'test-session-id' };
      mockReq.query = {};
      (prisma.verificationSession.findUnique as jest.Mock).mockResolvedValue(mockSession);

      await requireValidToken(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect((mockReq as any).sessionId).toBe('test-session-id');
      expect((mockReq as any).discordUserId).toBe('test-discord-id');
    });

    it('should proceed with valid token in query', async () => {
      const mockSession = {
        id: 'test-session-id',
        discordUserId: 'test-discord-id',
        expiresAt: new Date(Date.now() + 3600000),
        used: false
      };

      mockReq.query = { token: 'test-session-id' };
      mockReq.body = {};
      (prisma.verificationSession.findUnique as jest.Mock).mockResolvedValue(mockSession);

      await requireValidToken(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect((mockReq as any).sessionId).toBe('test-session-id');
      expect((mockReq as any).discordUserId).toBe('test-discord-id');
    });

    it('should reject request without token', () => {
      mockReq.body = {};
      mockReq.query = {};
      mockReq.headers = {};

      requireValidToken(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Token required',
        message: 'Verification token is required'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject invalid token', async () => {
      mockReq.body = { token: 'invalid-token' };
      mockReq.query = {};
      (prisma.verificationSession.findUnique as jest.Mock).mockResolvedValue(null);

      await requireValidToken(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Invalid token',
        message: 'Session not found'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('checkVerificationStatus', () => {
    it('should proceed when user is not verified', async () => {
      mockReq = { discordUserId: 'test-discord-id' };
      (prisma.adminVerification.findUnique as jest.Mock).mockResolvedValue(null);

      await checkVerificationStatus(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should proceed when user verification is not active', async () => {
      mockReq = { discordUserId: 'test-discord-id' };
      (prisma.adminVerification.findUnique as jest.Mock).mockResolvedValue({
        discordUserId: 'test-discord-id',
        isActive: false
      });

      await checkVerificationStatus(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should reject when user is already verified', async () => {
      mockReq = { discordUserId: 'test-discord-id' };
      (prisma.adminVerification.findUnique as jest.Mock).mockResolvedValue({
        discordUserId: 'test-discord-id',
        isActive: true,
        uniqueIdentifier: 'test-identifier'
      });

      await checkVerificationStatus(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(409);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Already verified',
        message: 'User already has active admin verification',
        uniqueIdentifier: 'test-identifier'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject when discordUserId is missing', async () => {
      mockReq = {};

      await checkVerificationStatus(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'User ID not found',
        message: 'Discord user ID is required'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should handle database errors gracefully', async () => {
      mockReq = { discordUserId: 'test-discord-id' };
      (prisma.adminVerification.findUnique as jest.Mock).mockRejectedValue(new Error('Database error'));

      await checkVerificationStatus(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Internal server error',
        message: 'Failed to check verification status'
      });
      expect(logger.error).toHaveBeenCalledWith('Verification status check error:', expect.any(Error));
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('checkVerificationRateLimit', () => {
    beforeEach(() => {
      // Clear the in-memory rate limit map by resetting modules
      jest.resetModules();
    });

    it('should return true for first attempt', () => {
      const result = checkVerificationRateLimit('test-user-id', 3);

      expect(result).toBe(true);
    });

    it('should return true for attempts within limit', () => {
      checkVerificationRateLimit('test-user-id', 3);
      checkVerificationRateLimit('test-user-id', 3);

      const result = checkVerificationRateLimit('test-user-id', 3);
      expect(result).toBe(true);
    });

    it('should return false when limit exceeded', () => {
      checkVerificationRateLimit('test-user-id', 2);
      checkVerificationRateLimit('test-user-id', 2);

      const result = checkVerificationRateLimit('test-user-id', 2);
      expect(result).toBe(false);
    });

    it('should log rate limit exceeded', () => {
      checkVerificationRateLimit('test-user-id', 1);

      const result = checkVerificationRateLimit('test-user-id', 1);
      expect(result).toBe(false);
      expect(auditLogger.logSecurityEvent).toHaveBeenCalledWith(
        'rate_limit_exceeded',
        expect.objectContaining({
          attempts: 1,
          maxAttempts: 1
        }),
        'test-user-id'
      );
    });
  });

  describe('cleanupRateLimitEntries', () => {
    it('should clean up expired entries', () => {
      // The cleanup function should work without throwing errors
      expect(() => cleanupRateLimitEntries()).not.toThrow();
    });
  });

  describe('validateAndSanitize', () => {
    const testSchema = Joi.object({
      name: Joi.string().required(),
      age: Joi.number().integer().min(0)
    });

    it('should validate and sanitize valid input', () => {
      const middleware = validateAndSanitize(testSchema);
      mockReq.body = { name: 'test', age: '25', extra: 'field' };

      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.body).toEqual({ name: 'test', age: 25 });
      expect(mockNext).toHaveBeenCalled();
    });

    it('should reject invalid input', () => {
      const middleware = validateAndSanitize(testSchema);
      mockReq.body = { name: '', age: 'invalid' };
      mockReq.ip = '127.0.0.1';
      mockReq.method = 'POST';
      mockReq.url = '/test';
      mockReq.get = jest.fn().mockReturnValue('test-agent');

      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Validation failed',
        message: 'Invalid input data',
        details: expect.any(Array)
      });
      expect(logger.warn).toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should detect and reject suspicious patterns', () => {
      const middleware = validateAndSanitize(testSchema);
      mockReq.body = { name: '<script>alert("xss")</script>', age: 25 };
      mockReq.ip = '127.0.0.1';
      mockReq.method = 'POST';
      mockReq.url = '/test';
      mockReq.get = jest.fn().mockReturnValue('test-agent');

      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Invalid content',
        message: 'Request contains potentially malicious content'
      });
      expect(logger.warn).toHaveBeenCalledWith(
        'Suspicious patterns detected in request body',
        expect.objectContaining({
          ip: '127.0.0.1',
          method: 'POST',
          url: '/test'
        })
      );
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('validateParams', () => {
    const testSchema = Joi.object({
      id: Joi.string().required()
    });

    it('should validate valid route parameters', () => {
      const middleware = validateParams(testSchema);
      mockReq.params = { id: 'test-id' };

      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.params).toEqual({ id: 'test-id' });
      expect(mockNext).toHaveBeenCalled();
    });

    it('should reject invalid route parameters', () => {
      const middleware = validateParams(testSchema);
      mockReq.params = {};
      mockReq.ip = '127.0.0.1';
      mockReq.method = 'GET';
      mockReq.url = '/test';

      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Validation failed',
        message: 'Invalid route parameters',
        details: expect.any(Array)
      });
      expect(logger.warn).toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('securityValidation', () => {
    it('should pass validation for clean content', () => {
      mockReq.body = { message: 'clean message' };
      mockReq.query = { param: 'clean param' };

      securityValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should reject content with suspicious patterns', () => {
      mockReq.body = { message: '<script>alert("xss")</script>' };
      mockReq.query = { param: 'clean' };
      mockReq.ip = '127.0.0.1';
      mockReq.method = 'POST';
      mockReq.url = '/test';
      mockReq.get = jest.fn().mockReturnValue('test-agent');

      securityValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Invalid content',
        message: 'Request contains potentially malicious content'
      });
      expect(logger.warn).toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('checkValidationRateLimit', () => {
    it('should return true for first validation failure', () => {
      const result = checkValidationRateLimit('test-identifier', 10);

      expect(result).toBe(true);
    });

    it('should return false when validation failure limit exceeded', () => {
      for (let i = 0; i < 10; i++) {
        checkValidationRateLimit('test-identifier', 10);
      }

      const result = checkValidationRateLimit('test-identifier', 10);
      expect(result).toBe(false);
    });
  });

  describe('cleanupValidationFailureEntries', () => {
    it('should clean up expired validation failure entries', () => {
      expect(() => cleanupValidationFailureEntries()).not.toThrow();
    });
  });

  describe('validateRequestSize', () => {
    it('should proceed for GET requests', () => {
      mockReq.method = 'GET';

      validateRequestSize(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should proceed for POST with valid size', () => {
      mockReq.method = 'POST';
      mockReq.get = jest.fn().mockReturnValue('1024'); // 1KB

      validateRequestSize(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should reject POST without content-length header', () => {
      mockReq.method = 'POST';
      mockReq.get = jest.fn().mockReturnValue(undefined);
      mockReq.ip = '127.0.0.1';
      mockReq.method = 'POST';
      mockReq.url = '/test';

      validateRequestSize(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Invalid request',
        message: 'Invalid or missing content-length header'
      });
      expect(logger.warn).toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject POST with size exceeding limit', () => {
      mockReq.method = 'POST';
      mockReq.get = jest.fn().mockReturnValue((6 * 1024 * 1024).toString()); // 6MB
      mockReq.ip = '127.0.0.1';
      mockReq.method = 'POST';
      mockReq.url = '/test';

      validateRequestSize(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(413);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Request too large',
        message: 'Request body exceeds maximum allowed size',
        maxSize: '5MB'
      });
      expect(logger.warn).toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject POST with empty body', () => {
      mockReq.method = 'POST';
      mockReq.get = jest.fn().mockReturnValue('0');
      mockReq.ip = '127.0.0.1';
      mockReq.url = '/test';
      mockReq.headers = {};

      validateRequestSize(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Invalid request',
        message: 'Invalid or missing content-length header'
      });
      expect(logger.warn).toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('validateRequestHeaders', () => {
    it('should proceed with valid headers', () => {
      mockReq.get = jest.fn((header: string) => {
        if (header === 'User-Agent') return 'test-agent';
        if (header === 'Content-Type') return 'application/json';
        return undefined;
      });

      validateRequestHeaders(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should log missing User-Agent', () => {
      mockReq.get = jest.fn().mockReturnValue(undefined);
      mockReq.ip = '127.0.0.1';
      mockReq.method = 'GET';
      mockReq.url = '/test';

      validateRequestHeaders(mockReq as Request, mockRes as Response, mockNext);

      expect(logger.warn).toHaveBeenCalledWith(
        'Request without User-Agent header',
        expect.objectContaining({
          ip: '127.0.0.1',
          method: 'GET',
          url: '/test'
        })
      );
      expect(mockNext).toHaveBeenCalled();
    });

    it('should reject unsupported Content-Type for POST', () => {
      mockReq.method = 'POST';
      mockReq.get = jest.fn((header: string) => {
        if (header === 'Content-Type') return 'text/html';
        return undefined;
      });
      mockReq.ip = '127.0.0.1';
      mockReq.method = 'POST';
      mockReq.url = '/test';

      validateRequestHeaders(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(415);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Unsupported media type',
        message: 'Content-Type must be application/json or application/x-www-form-urlencoded'
      });
      expect(logger.warn).toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should log suspicious headers', () => {
      mockReq.get = jest.fn((header: string) => {
        if (header === 'x-forwarded-host') return 'malicious.com';
        return undefined;
      });
      mockReq.ip = '127.0.0.1';
      mockReq.method = 'GET';
      mockReq.url = '/test';

      validateRequestHeaders(mockReq as Request, mockRes as Response, mockNext);

      expect(logger.warn).toHaveBeenCalledWith(
        'Suspicious header detected',
        expect.objectContaining({
          header: 'x-forwarded-host',
          value: 'malicious.com'
        })
      );
      expect(mockNext).toHaveBeenCalled();
    });
  });
});