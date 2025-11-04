import { Request, Response, NextFunction } from 'express';
import Joi from 'joi';
import { logger } from '../utils/logger';

/**
 * Enhanced input validation middleware with sanitization for request body
 */
export function validateAndSanitize(schema: Joi.ObjectSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Additional pre-validation security checks
      const body = JSON.stringify(req.body);

      // Check for potentially malicious patterns before validation
      if (containsSuspiciousPatterns(body)) {
        logger.warn('Suspicious patterns detected in request body', {
          ip: req.ip,
          method: req.method,
          url: req.url,
          userAgent: req.get('User-Agent'),
          contentLength: body.length
        });

        return res.status(400).json({
          error: 'Invalid content',
          message: 'Request contains potentially malicious content',
        });
      }

      const { error, value } = schema.validate(req.body, {
        abortEarly: false,
        stripUnknown: true,
        convert: true
      });

      if (error) {
        logger.warn('Input validation failed', {
          ip: req.ip,
          method: req.method,
          url: req.url,
          errors: error.details.map(detail => ({
            field: detail.path.join('.'),
            message: detail.message,
            value: detail.context?.value
          }))
        });

        return res.status(400).json({
          error: 'Validation failed',
          message: 'Invalid input data',
          details: error.details.map(detail => ({
            field: detail.path.join('.'),
            message: detail.message
          }))
        });
      }

      // Sanitize the request body with enhanced protection
      req.body = sanitizeRequestBody(value);
      next();
    } catch (error) {
      logger.error('Validation middleware error:', error);
      return res.status(500).json({
        error: 'Validation processing error',
        message: 'An error occurred while processing request validation'
      });
    }
  };
}

/**
 * Check for suspicious patterns that indicate potential attacks
 */
function containsSuspiciousPatterns(content: string): boolean {
  const suspiciousPatterns = [
    // XSS patterns
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /vbscript:/gi,
    /data:/gi,
    /file:/gi,
    /<iframe\b[^>]*>/gi,
    /<object\b[^>]*>/gi,
    /<embed\b[^>]*>/gi,
    /<link\b[^>]*>/gi,
    /<style\b[^>]*>/gi,
    /<meta\b[^>]*>/gi,

    // SQL injection patterns
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)/gi,
    /((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/gi,
    /((\%27)|(\'))((\%6D)|m|(\%4D))((\%77)|w|(\%57))/gi,
    /(\b(OR|AND)\b\s+['"]\s*[=%])/gi,

    // Command injection patterns
    /[;&|`$()]/,
    /(\b(rm|del|cmd|powershell|bash|sh|chmod|mv|cp)\b)/gi,
    /(\b(wget|curl|nc|netcat|telnet|ssh)\b)/gi,

    // Path traversal patterns
    /(\.\.\/)+/,
    /(\.\.\\)+/,
    /%2e%2e%2f/gi,

    // Protocol abuse
    /@import/gi,
    /expression\s*\(/gi,
    /behavior\s*:/gi,
    /-moz-binding/gi,

    // Event handlers
    /on\w+\s*=/gi,
  ];

  return suspiciousPatterns.some(pattern => pattern.test(content));
}

/**
 * Deep sanitize request body to remove potentially dangerous content
 */
function sanitizeRequestBody(obj: any): any {
  if (typeof obj === 'string') {
    return obj
      .replace(/[\x00-\x1F\x7F]/g, '') // Remove control characters
      .replace(/<[^>]*>/g, '') // Remove HTML tags
      .replace(/javascript:/gi, '') // Remove javascript: protocol
      .replace(/vbscript:/gi, '') // Remove vbscript: protocol
      .replace(/data:/gi, '') // Remove data: protocol
      .replace(/file:/gi, '') // Remove file: protocol
      .replace(/@import/gi, '') // Remove @import
      .replace(/expression\s*\(/gi, '') // Remove expression()
      .replace(/behavior\s*:/gi, '') // Remove behavior:
      .replace(/on\w+\s*=/gi, '') // Remove event handlers
      .trim();
  }

  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeRequestBody(item));
  }

  if (obj && typeof obj === 'object') {
    const sanitized: any = {};
    for (const [key, value] of Object.entries(obj)) {
      // Sanitize keys as well
      const sanitizedKey = String(key).replace(/[^a-zA-Z0-9_-]/g, '');
      if (sanitizedKey) {
        sanitized[sanitizedKey] = sanitizeRequestBody(value);
      }
    }
    return sanitized;
  }

  return obj;
}

/**
 * Enhanced input validation middleware for route parameters
 */
export function validateParams(schema: Joi.ObjectSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    const { error, value } = schema.validate(req.params, {
      abortEarly: false,
      stripUnknown: true,
      convert: true
    });

    if (error) {
      logger.warn('Parameter validation failed', {
        ip: req.ip,
        method: req.method,
        url: req.url,
        errors: error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message,
          value: detail.context?.value
        }))
      });

      return res.status(400).json({
        error: 'Validation failed',
        message: 'Invalid route parameters',
        details: error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message
        }))
      });
    }

    // Sanitize the request parameters
    req.params = value;
    next();
  };
}

/**
 * Security validation middleware for common attack patterns
 */
export function securityValidation(req: Request, res: Response, next: NextFunction) {
  const body = JSON.stringify(req.body);
  const query = JSON.stringify(req.query);

  // Check for common attack patterns
  const suspiciousPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /vbscript:/gi,
    /onload\s*=/gi,
    /onerror\s*=/gi,
    /onclick\s*=/gi,
    /<iframe\b[^>]*>/gi,
    /<object\b[^>]*>/gi,
    /<embed\b[^>]*>/gi,
    /expression\s*\(/gi,
    /@import/gi,
    /behavior\s*:/gi
  ];

  const allContent = `${body} ${query}`;

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(allContent)) {
      logger.warn('Suspicious content detected', {
        ip: req.ip,
        method: req.method,
        url: req.url,
        userAgent: req.get('User-Agent'),
        pattern: pattern.source
      });

      return res.status(400).json({
        error: 'Invalid content',
        message: 'Request contains potentially malicious content'
      });
    }
  }

  next();
}

/**
 * Rate limiting for validation failures to prevent brute force attacks
 */
const validationFailureCounts = new Map<string, { count: number; resetTime: number }>();

export function checkValidationRateLimit(identifier: string, maxFailures: number = 10): boolean {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const failureCount = validationFailureCounts.get(identifier);

  if (!failureCount || now > failureCount.resetTime) {
    // Reset or initialize failure counter
    validationFailureCounts.set(identifier, {
      count: 1,
      resetTime: now + windowMs,
    });
    return true;
  }

  if (failureCount.count >= maxFailures) {
    logger.warn(`Validation failure rate limit exceeded for ${identifier}`, {
      attempts: failureCount.count,
      maxFailures,
      resetTime: new Date(failureCount.resetTime).toISOString(),
      ip: identifier.includes(':') ? identifier : undefined
    });
    return false;
  }

  failureCount.count++;
  return true;
}

/**
 * Clean up expired validation failure entries
 */
export function cleanupValidationFailureEntries(): void {
  const now = Date.now();
  for (const [identifier, failure] of validationFailureCounts.entries()) {
    if (now > failure.resetTime) {
      validationFailureCounts.delete(identifier);
    }
  }
}

/**
 * Clear validation failure map for testing (only use in test environment)
 */
export function clearValidationFailureMapForTesting(): void {
  if (process.env.NODE_ENV === 'test') {
    validationFailureCounts.clear();
  }
}

// Clean up validation failure entries every 10 minutes
let validationFailureCleanupInterval: NodeJS.Timeout | null = null;

export function startValidationFailureCleanup(): void {
  if (!validationFailureCleanupInterval) {
    validationFailureCleanupInterval = setInterval(cleanupValidationFailureEntries, 10 * 60 * 1000);
  }
}

export function stopValidationFailureCleanup(): void {
  if (validationFailureCleanupInterval) {
    clearInterval(validationFailureCleanupInterval);
    validationFailureCleanupInterval = null;
  }
}

// Do NOT start cleanup automatically in test environment
if (process.env.NODE_ENV !== 'test') {
  startValidationFailureCleanup();
}

/**
 * Enhanced request size validation middleware with stricter limits
 */
export function validateRequestSize(req: Request, res: Response, next: NextFunction) {
  const contentLength = parseInt(req.get('content-length') || '0', 10);
  const maxSize = 5 * 1024 * 1024; // 5MB - reduced for better security
  const criticalSize = 1 * 1024 * 1024; // 1MB - critical size threshold

  // Skip content-length validation for methods that don't typically have a body
  const methodsWithoutBody = ['GET', 'HEAD', 'OPTIONS'];
  if (methodsWithoutBody.includes(req.method)) {
    next();
    return;
  }

  // Check if content-length header is missing or invalid for methods that should have a body
  if (!contentLength || contentLength < 0) {
    logger.warn('Invalid content-length header', {
      ip: req.ip,
      method: req.method,
      url: req.url,
      contentLength: req.get('content-length')
    });

    return res.status(400).json({
      error: 'Invalid request',
      message: 'Invalid or missing content-length header'
    });
  }

  // Critical size check - log and warn but still allow
  if (contentLength > criticalSize) {
    logger.warn('Large request size detected', {
      ip: req.ip,
      method: req.method,
      url: req.url,
      size: contentLength,
      criticalSize
    });
  }

  // Maximum size check - reject
  if (contentLength > maxSize) {
    logger.warn('Request size exceeded', {
      ip: req.ip,
      method: req.method,
      url: req.url,
      size: contentLength,
      maxSize
    });

    return res.status(413).json({
      error: 'Request too large',
      message: 'Request body exceeds maximum allowed size',
      maxSize: `${maxSize / 1024 / 1024}MB`
    });
  }

  // Empty body check for POST/PUT requests - only reject if explicitly 0
  if ((req.method === 'POST' || req.method === 'PUT') && contentLength === 0) {
    logger.warn('Empty body for POST/PUT request', {
      ip: req.ip,
      method: req.method,
      url: req.url
    });

    return res.status(400).json({
      error: 'Invalid request',
      message: 'Request body cannot be empty'
    });
  }

  next();
}

/**
 * Validate request headers for security
 */
export function validateRequestHeaders(req: Request, res: Response, next: NextFunction) {
  const userAgent = req.get('User-Agent');
  const contentType = req.get('Content-Type');
  const accept = req.get('Accept');

  // Log missing User-Agent (potential bot)
  if (!userAgent) {
    logger.warn('Request without User-Agent header', {
      ip: req.ip,
      method: req.method,
      url: req.url
    });
  }

  // Validate Content-Type for POST/PUT requests
  if ((req.method === 'POST' || req.method === 'PUT') && contentType) {
    const allowedTypes = ['application/json', 'application/x-www-form-urlencoded'];
    if (!allowedTypes.some(type => contentType.toLowerCase().includes(type.toLowerCase()))) {
      logger.warn('Unsupported content type', {
        ip: req.ip,
        method: req.method,
        url: req.url,
        contentType
      });

      return res.status(415).json({
        error: 'Unsupported media type',
        message: 'Content-Type must be application/json or application/x-www-form-urlencoded'
      });
    }
  }

  // Check for potentially malicious headers
  const suspiciousHeaders = [
    'x-forwarded-host',
    'x-original-url',
    'x-rewrite-url'
  ];

  for (const header of suspiciousHeaders) {
    if (req.get(header)) {
      logger.warn('Suspicious header detected', {
        ip: req.ip,
        method: req.method,
        url: req.url,
        header,
        value: req.get(header)
      });
    }
  }

  next();
}