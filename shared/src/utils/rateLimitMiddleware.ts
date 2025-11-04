/**
 * Citadel 2.0 Phase 2.4 - Universal Rate Limiting Middleware
 * Multi-layer DoS protection middleware for Express and Next.js
 */

import { Request, Response, NextFunction } from 'express';
import { rateLimitManager } from '../utils/universalRateLimiter';

export interface RateLimitMiddlewareOptions {
  endpoint?: string;
  privilegeLevel?: 'user' | 'admin' | 'service';
  skipRateLimit?: (req: Request) => boolean;
  customIdentifier?: (req: Request) => string;
  headers?: boolean;
}

export interface RateLimitContext {
  endpoint: string;
  identifier: string;
  privilegeLevel: 'user' | 'admin' | 'service';
  userId?: string;
  ip?: string;
  authenticated?: boolean;
}

/**
 * Express Rate Limiting Middleware
 */
export function rateLimitMiddleware(options: RateLimitMiddlewareOptions = {}) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Determine endpoint
      const endpoint = options.endpoint || req.route?.path || req.path || 'unknown';
      
      // Skip rate limiting if configured
      if (options.skipRateLimit && options.skipRateLimit(req)) {
        return next();
      }

      // Get client identifier
      const identifier = options.customIdentifier 
        ? options.customIdentifier(req)
        : getClientIdentifier(req);

      // Get request context
      const context = extractRateLimitContext(req, endpoint, identifier, options.privilegeLevel);

      // Check rate limiting
      const rateLimitResult = await rateLimitManager.isRateLimited(
        context.endpoint,
        context.identifier,
        {
          userId: context.userId,
          ip: context.ip,
          authenticated: context.authenticated,
          privilegeLevel: context.privilegeLevel
        }
      );

      // Set rate limit headers if enabled
      if (options.headers !== false && rateLimitResult.headers) {
        Object.entries(rateLimitResult.headers).forEach(([key, value]) => {
          res.setHeader(key, value);
        });
      }

      // Handle rate limit exceeded
      if (rateLimitResult.limited) {
        const retrySeconds = Math.round((rateLimitResult.msBeforeNext || 0) / 1000);
        
        // Log rate limit violation
        console.warn(`🚨 Rate limit exceeded for ${context.endpoint}`, {
          identifier: context.identifier,
          ip: context.ip,
          userAgent: req.get('User-Agent'),
          retryAfter: retrySeconds,
          isAbuse: rateLimitResult.isAbuse
        });

        // Return 429 response
        res.status(429).json({
          error: 'Rate limit exceeded',
          message: 'Too many requests. Please try again later.',
          retryAfter: retrySeconds,
          limit: rateLimitResult.headers?.['X-RateLimit-Limit'],
          remaining: rateLimitResult.headers?.['X-RateLimit-Remaining'],
          reset: rateLimitResult.headers?.['X-RateLimit-Reset'],
          isAbuse: rateLimitResult.isAbuse
        });
        
        return;
      }

      // Add rate limit info to request for downstream use
      (req as any).rateLimitInfo = {
        endpoint: context.endpoint,
        identifier: context.identifier,
        privilegeLevel: context.privilegeLevel,
        remaining: rateLimitResult.remainingPoints,
        resetTime: rateLimitResult.msBeforeNext
      };

      next();
    } catch (error) {
      console.error('Rate limiting middleware error:', error);
      // On error, allow request but log for monitoring
      next();
    }
  };
}

/**
 * Next.js API Route Handler
 */
export function withRateLimit(options: RateLimitMiddlewareOptions = {}) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Determine endpoint
      const endpoint = options.endpoint || req.url || '/api/unknown';
      
      // Skip rate limiting if configured
      if (options.skipRateLimit && options.skipRateLimit(req)) {
        return next();
      }

      // Get client identifier
      const identifier = options.customIdentifier 
        ? options.customIdentifier(req)
        : getClientIdentifier(req);

      // Get request context
      const context = extractRateLimitContext(req, endpoint, identifier, options.privilegeLevel);

      // Check rate limiting
      const rateLimitResult = await rateLimitManager.isRateLimited(
        context.endpoint,
        context.identifier,
        {
          userId: context.userId,
          ip: context.ip,
          authenticated: context.authenticated,
          privilegeLevel: context.privilegeLevel
        }
      );

      // Set rate limit headers
      if (options.headers !== false && rateLimitResult.headers) {
        Object.entries(rateLimitResult.headers).forEach(([key, value]) => {
          res.setHeader(key, value);
        });
      }

      // Handle rate limit exceeded
      if (rateLimitResult.limited) {
        const retrySeconds = Math.round((rateLimitResult.msBeforeNext || 0) / 1000);
        
        console.warn(`🚨 Next.js API rate limit exceeded for ${context.endpoint}`, {
          identifier: context.identifier,
          ip: context.ip,
          userAgent: req.get('User-Agent'),
          retryAfter: retrySeconds,
          isAbuse: rateLimitResult.isAbuse
        });

        res.status(429).json({
          error: 'Rate limit exceeded',
          message: 'Too many requests. Please try again later.',
          retryAfter: retrySeconds,
          limit: rateLimitResult.headers?.['X-RateLimit-Limit'],
          remaining: rateLimitResult.headers?.['X-RateLimit-Remaining'],
          reset: rateLimitResult.headers?.['X-RateLimit-Reset'],
          isAbuse: rateLimitResult.isAbuse
        });
        
        return;
      }

      next();
    } catch (error) {
      console.error('Next.js rate limiting error:', error);
      next();
    }
  };
}

/**
 * Get client identifier for rate limiting
 */
function getClientIdentifier(req: Request): string {
  // Prefer user ID if authenticated
  const userId = (req as any).user?.id || (req as any).session?.userId;
  if (userId) {
    return `user:${userId}`;
  }

  // Fall back to IP address
  const ip = getClientIP(req);
  const forwardedFor = req.get('X-Forwarded-For');
  const realIP = req.get('X-Real-IP');
  
  // Use the most specific IP available
  if (forwardedFor) {
    return `ip:${forwardedFor.split(',')[0].trim()}`;
  } else if (realIP) {
    return `ip:${realIP}`;
  } else {
    return `ip:${ip}`;
  }
}

/**
 * Extract client IP address
 */
function getClientIP(req: Request): string {
  const forwarded = req.get('X-Forwarded-For');
  const realIP = req.get('X-Real-IP');
  
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  
  if (realIP) {
    return realIP;
  }
  
  return req.ip || req.connection.remoteAddress || '0.0.0.0';
}

/**
 * Extract rate limit context from request
 */
function extractRateLimitContext(
  req: Request,
  endpoint: string,
  identifier: string,
  privilegeLevel?: 'user' | 'admin' | 'service'
): RateLimitContext {
  const userId = (req as any).user?.id || (req as any).session?.userId;
  const ip = getClientIP(req);
  const authenticated = !!(userId || (req as any).apiKey);
  
  // Determine privilege level
  let determinedPrivilege: 'user' | 'admin' | 'service' = 'user';
  
  if (privilegeLevel) {
    determinedPrivilege = privilegeLevel;
  } else if ((req as any).isAdmin || (req as any).apiKey) {
    determinedPrivilege = 'admin';
  } else if (userId) {
    determinedPrivilege = 'user';
  }
  
  // Handle service accounts or API keys
  if ((req as any).apiKey) {
    determinedPrivilege = 'service';
  }

  return {
    endpoint: sanitizeEndpoint(endpoint),
    identifier: identifier,
    privilegeLevel: determinedPrivilege,
    userId,
    ip,
    authenticated
  };
}

/**
 * Sanitize endpoint for rate limiting key
 */
function sanitizeEndpoint(endpoint: string): string {
  // Convert to lowercase
  let sanitized = endpoint.toLowerCase();
  
  // Replace dynamic segments with placeholders
  sanitized = sanitized.replace(/\/\d+/g, '/:id');
  sanitized = sanitized.replace(/\/[a-f0-9-]{36}/g, '/:uuid');
  sanitized = sanitized.replace(/\/[a-zA-Z0-9-_]+/g, '/:param');
  
  // Remove query parameters
  const questionIndex = sanitized.indexOf('?');
  if (questionIndex !== -1) {
    sanitized = sanitized.substring(0, questionIndex);
  }
  
  // Remove trailing slashes
  sanitized = sanitized.replace(/\/+$/, '');
  
  return sanitized || 'unknown';
}

/**
 * Endpoint-specific middleware configurations
 */
export const rateLimitConfigs = {
  // Authentication endpoints
  auth: {
    endpoint: 'auth-login',
    privilegeLevel: 'user' as const,
    headers: true
  },
  
  // Admin endpoints
  admin: {
    endpoint: 'admin-stats',
    privilegeLevel: 'admin' as const,
    headers: true
  },
  
  adminVerify: {
    endpoint: 'admin-verify-user',
    privilegeLevel: 'admin' as const,
    headers: true
  },
  
  adminRevoke: {
    endpoint: 'admin-revoke-user',
    privilegeLevel: 'admin' as const,
    headers: true
  },
  
  adminSessions: {
    endpoint: 'admin-sessions',
    privilegeLevel: 'admin' as const,
    headers: true
  },
  
  adminCleanup: {
    endpoint: 'admin-cleanup',
    privilegeLevel: 'admin' as const,
    headers: true
  },
  
  // Verification endpoints
  verifyProof: {
    endpoint: 'verify-proof',
    privilegeLevel: 'user' as const,
    headers: true
  },
  
  verifyStatus: {
    endpoint: 'verify-status',
    privilegeLevel: 'user' as const,
    headers: true
  },
  
  verifyWebhook: {
    endpoint: 'verify-webhook',
    privilegeLevel: 'service' as const,
    headers: true
  },
  
  // Discord endpoints
  discordUser: {
    endpoint: 'discord-user',
    privilegeLevel: 'user' as const,
    headers: true
  },
  
  discordRegister: {
    endpoint: 'discord-register',
    privilegeLevel: 'user' as const,
    headers: true
  },
  
  discordVerify: {
    endpoint: 'discord-verify',
    privilegeLevel: 'user' as const,
    headers: true
  },
  
  discordRoleUpdate: {
    endpoint: 'discord-role-update',
    privilegeLevel: 'admin' as const,
    headers: true
  },
  
  discordHealth: {
    endpoint: 'discord-health',
    privilegeLevel: 'service' as const,
    headers: true
  },
  
  // Webhook endpoints
  webhookDiscord: {
    endpoint: 'webhook-discord',
    privilegeLevel: 'service' as const,
    headers: true
  },
  
  webhookVerification: {
    endpoint: 'webhook-verification',
    privilegeLevel: 'service' as const,
    headers: true
  },
  
  webhookHealth: {
    endpoint: 'webhook-health',
    privilegeLevel: 'service' as const,
    headers: true
  },
  
  // Security endpoints
  securityXSS: {
    endpoint: 'security-xss-report',
    privilegeLevel: 'user' as const,
    headers: true
  },
  
  securityCSP: {
    endpoint: 'security-csp-report',
    privilegeLevel: 'user' as const,
    headers: true
  },
  
  securityHSTS: {
    endpoint: 'security-hsts-report',
    privilegeLevel: 'user' as const,
    headers: true
  },
  
  securityCT: {
    endpoint: 'security-ct-report',
    privilegeLevel: 'user' as const,
    headers: true
  },
  
  securityNEL: {
    endpoint: 'security-nel-report',
    privilegeLevel: 'user' as const,
    headers: true
  },
  
  securityReports: {
    endpoint: 'security-reports',
    privilegeLevel: 'user' as const,
    headers: true
  },
  
  securityHeaders: {
    endpoint: 'security-headers',
    privilegeLevel: 'user' as const,
    headers: true
  },
  
  // Health endpoints
  health: {
    endpoint: 'health',
    privilegeLevel: 'service' as const,
    headers: true
  },
  
  metrics: {
    endpoint: 'metrics',
    privilegeLevel: 'admin' as const,
    headers: true
  }
};

/**
 * Utility function to get rate limit stats
 */
export function getRateLimitStats() {
  return rateLimitManager.getStats();
}

/**
 * Utility function to reset rate limit (admin only)
 */
export async function resetRateLimit(endpoint: string, identifier: string) {
  return rateLimitManager.resetRateLimit(endpoint, identifier);
}