import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

/**
 * Comprehensive request logging middleware for security monitoring
 */
export function securityLogger(req: Request, res: Response, next: NextFunction) {
  const startTime = Date.now();
  const timestamp = new Date().toISOString();

  // Log incoming request
  logger.info('Incoming request', {
    timestamp,
    method: req.method,
    url: req.url,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    contentType: req.get('Content-Type'),
    contentLength: req.get('Content-Length'),
    origin: req.get('Origin'),
    referer: req.get('Referer'),
    xForwardedFor: req.get('X-Forwarded-For'),
    xRealIP: req.get('X-Real-IP'),
    // Only log body for non-sensitive endpoints and in development
    ...(process.env.NODE_ENV === 'development' &&
        req.body &&
        typeof req.body === 'object' &&
        !req.url.includes('/verify/proof') &&
        !req.url.includes('/admin') && {
          body: req.body
        })
  });

  // Capture response data
  const originalSend = res.send.bind(res);
  let responseBody = '';

  res.send = (data: any) => {
    responseBody = typeof data === 'string' ? data : JSON.stringify(data);
    return originalSend(data);
  };

  // Log response
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const statusCode = res.statusCode;

    // Log based on status code severity
    if (statusCode >= 500) {
      logger.error('Server error response', {
        timestamp,
        method: req.method,
        url: req.url,
        statusCode,
        duration,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        error: responseBody.substring(0, 500) // Limit error message length
      });
    } else if (statusCode >= 400) {
      logger.warn('Client error response', {
        timestamp,
        method: req.method,
        url: req.url,
        statusCode,
        duration,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        error: responseBody.substring(0, 300)
      });
    } else if (statusCode >= 300) {
      logger.info('Redirection response', {
        timestamp,
        method: req.method,
        url: req.url,
        statusCode,
        duration,
        ip: req.ip
      });
    } else {
      // Only log successful responses in development or for sensitive endpoints
      if (process.env.NODE_ENV === 'development' ||
          req.url.includes('/health') ||
          req.url.includes('/status')) {
        logger.info('Successful response', {
          timestamp,
          method: req.method,
          url: req.url,
          statusCode,
          duration,
          ip: req.ip
        });
      }
    }

    // Security monitoring: Log suspicious patterns
    if (duration > 10000) { // Requests taking more than 10 seconds
      logger.warn('Slow request detected', {
        timestamp,
        method: req.method,
        url: req.url,
        duration,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
    }

    // Log potential DDoS patterns (multiple requests from same IP in short time)
    // This is a simplified check - in production, you'd use Redis or similar for tracking
    if (req.url.includes('/verify') && statusCode === 429) {
      logger.warn('Rate limit hit on verification endpoint', {
        timestamp,
        method: req.method,
        url: req.url,
        statusCode,
        ip: req.ip
      });
    }
  });

  next();
}

/**
 * Rate limiting tracker for security monitoring
 */
const requestCounts = new Map<string, { count: number; windowStart: number }>();

export function rateLimitTracker(req: Request, res: Response, next: NextFunction) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 60000; // 1 minute window
  const maxRequests = 50; // Max requests per minute per IP

  const existing = requestCounts.get(ip);

  if (!existing || (now - existing.windowStart) > windowMs) {
    // New window or expired window
    requestCounts.set(ip, { count: 1, windowStart: now });
  } else {
    existing.count++;

    // Log if approaching rate limit
    if (existing.count >= maxRequests * 0.8) {
      logger.warn('High request rate detected', {
        ip,
        count: existing.count,
        maxRequests,
        windowStart: new Date(existing.windowStart)
      });
    }

    // Block if rate limit exceeded
    if (existing.count > maxRequests) {
      logger.warn('Rate limit exceeded', {
        ip,
        count: existing.count,
        maxRequests,
        windowStart: new Date(existing.windowStart)
      });

      // Send 429 Too Many Requests response
      return res.status(429).json({
        error: 'Too Many Requests',
        message: 'Rate limit exceeded. Please try again later.',
        retryAfter: Math.ceil((windowMs - (now - existing.windowStart)) / 1000)
      });
    }
  }

  next();
}

/**
 * Comprehensive security headers middleware with enhanced protection
 */
export function securityHeaders(req: Request, res: Response, next: NextFunction) {
  const isProduction = process.env.NODE_ENV === 'production';
  const isTest = process.env.NODE_ENV === 'test';
  
  // Core Security Headers
  // 1. X-Content-Type-Options - Prevent MIME sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // 2. X-Frame-Options - Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  // 3. X-XSS-Protection - Enable browser XSS protection
  res.setHeader('X-XSS-Protection', '1; mode=block; report=/api/security/xss-report');
  
  // 4. Referrer-Policy - Control referrer information leakage
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // 5. X-Permitted-Cross-Domain-Policies - Restrict cross-domain policies
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  
  // 6. X-Download-Options - IE8 download protection
  res.setHeader('X-Download-Options', 'noopen');
  
  // 7. X-DNS-Prefetch-Control - Control DNS prefetching
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  
  // 8. Permissions-Policy - Control browser features
  const permissionsPolicy = [
    'accelerometer=()',
    'ambient-light-sensor=()',
    'autoplay=()',
    'battery=()',
    'camera=()',
    'cross-origin-isolated=()',
    'display-capture=()',
    'document-domain=()',
    'encrypted-media=()',
    'execution-while-not-rendered=()',
    'execution-while-out-of-viewport=()',
    'fullscreen=()',
    'geolocation=()',
    'gyroscope=()',
    'keyboard-map=()',
    'magnetometer=()',
    'microphone=()',
    'midi=()',
    'navigation-override=()',
    'payment=()',
    'picture-in-picture=()',
    'publickey-credentials-get=()',
    'screen-wake-lock=()',
    'sync-xhr=()',
    'usb=()',
    'web-share=()',
    'xr-spatial-tracking=()'
  ].join(', ');
  res.setHeader('Permissions-Policy', permissionsPolicy);
  
  // 9. Cross-Origin-Opener-Policy - Prevent cross-origin attacks
  res.setHeader('Cross-Origin-Opener-Policy', isProduction ? 'same-origin' : 'same-origin-allow-popups');
  
  // 10. Cross-Origin-Embedder-Policy - Control cross-origin resource embedding
  res.setHeader('Cross-Origin-Embedder-Policy', isProduction ? 'require-corp' : 'require-corp');
  
  // 11. Cross-Origin-Resource-Policy - Control resource sharing
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  
  // Content Security Policy
  if (isProduction) {
    res.setHeader('Content-Security-Policy', [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self'",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-src 'none'",
      "media-src 'none'",
      "worker-src 'none'",
      "manifest-src 'self'",
      "upgrade-insecure-requests",
      "block-all-mixed-content"
    ].join('; '));
  } else {
    res.setHeader('Content-Security-Policy', [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self'",
      "connect-src 'self' ws: wss:",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-src 'none'",
      "media-src 'none'",
      "worker-src 'none'",
      "manifest-src 'self'"
    ].join('; '));
  }
  
  // Transport Security Headers
  if (isProduction) {
    // HSTS - Enforce HTTPS
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload; report-uri=/api/security/hsts-report');
    
    // Expect-CT - Certificate Transparency enforcement
    res.setHeader('Expect-CT', 'max-age=86400, enforce, report-uri=/api/security/ct-report');
    
    // Public-Key-Pins (deprecated but documented for legacy browser support)
    // Note: HPKP is deprecated by most browsers, but included for comprehensive coverage
    // res.setHeader('Public-Key-Pins', 'pin-sha256="base64=="; max-age=86400; includeSubDomains; report-uri=/api/security/hpkp-report');
  }
  
  // Reporting Endpoints
  const reportingEndpoints = isProduction
    ? 'default="/api/security/reports"'
    : 'default="/dev-api/security/reports"';
  res.setHeader('Reporting-Endpoints', reportingEndpoints);
  
  // Reporting-Collectors (for older browsers)
  res.setHeader('Report-To', JSON.stringify({
    group: 'default',
    max_age: 31536000,
    endpoints: [{
      url: isProduction ? '/api/security/reports' : '/dev-api/security/reports'
    }]
  }));
  
  // Cache Control for sensitive endpoints
  if (req.url.includes('/api/') || req.url.includes('/verify/') || req.url.includes('/admin/')) {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
  }
  
  // Additional security headers for production
  if (isProduction) {
    // Hide server information
    res.setHeader('Server', '');
    
    // Additional response headers for enhanced security
    res.setHeader('X-Response-Time', `${Date.now() - (req as any).startTime || 0}ms`);
  }
  
  // Add custom header for security compliance testing
  res.setHeader('X-Security-Headers', 'comprehensive-v1.0');
  
  next();
}

/**
 * Request timeout middleware
 */
export function requestTimeout(req: Request, res: Response, next: NextFunction) {
  // Set a reasonable timeout for requests (30 seconds)
  const timeout = setTimeout(() => {
    logger.warn('Request timeout', {
      method: req.method,
      url: req.url,
      ip: req.ip,
      duration: '30s'
    });

    if (!res.headersSent) {
      res.status(408).json({
        error: 'Request timeout',
        message: 'Request took too long to process'
      });
    }
  }, 30000);

  // Clear timeout when response is finished
  res.on('finish', () => {
    clearTimeout(timeout);
  });

  next();
}