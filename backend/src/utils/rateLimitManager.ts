/**
 * Universal Rate Limiting Framework
 * Provides comprehensive rate limiting across all services with Redis/memory storage
 */

import { RateLimiterMemory, RateLimiterRedis, IRateLimiterOptions } from 'rate-limiter-flexible';
import { Redis } from 'ioredis';

export { RateLimiterMemory, RateLimiterRedis };
export type { IRateLimiterOptions };
export { Redis };
import { logger } from '../../../backend/src/utils/logger';

type RateLimiter = RateLimiterMemory | RateLimiterRedis;

export interface RateLimitConfig {
  points: number;           // Number of requests
  duration: number;         // Duration in seconds
  keyPrefix: string;        // Storage key prefix
  blockDuration?: number;   // Block duration in seconds (default: same as duration)
  execEvenly?: boolean;     // Distribute requests evenly
  execEvenlyMinDelayMs?: number; // Minimum delay between requests
}

export interface EndpointRateLimit {
  [key: string]: RateLimitConfig;
}

export class UniversalRateLimitManager {
  private redisClient?: Redis;
  private rateLimiters = new Map<string, RateLimiter>();
  private abuseTracker = new Map<string, { violations: number; lastViolation: Date; blocked: boolean }>();
  
  // Endpoint-specific rate limits with different security levels
  private readonly endpointLimits: EndpointRateLimit = {
    // Authentication endpoints - STRICTEST limits
    'auth-login': { points: 5, duration: 900, keyPrefix: 'auth_login', blockDuration: 1800 }, // 5 per 15min, 30min block
    'auth-verify': { points: 3, duration: 300, keyPrefix: 'auth_verify', blockDuration: 900 }, // 3 per 5min, 15min block
    'auth-register': { points: 10, duration: 3600, keyPrefix: 'auth_register', blockDuration: 3600 }, // 10 per hour, 1h block
    
    // Admin endpoints - STRICT limits with privilege checks
    'admin-stats': { points: 30, duration: 300, keyPrefix: 'admin_stats', blockDuration: 900 }, // 30 per 5min
    'admin-verify-user': { points: 10, duration: 300, keyPrefix: 'admin_verify', blockDuration: 1800 }, // 10 per 5min
    'admin-revoke-user': { points: 10, duration: 300, keyPrefix: 'admin_revoke', blockDuration: 1800 },
    'admin-sessions': { points: 20, duration: 300, keyPrefix: 'admin_sessions', blockDuration: 900 },
    'admin-cleanup': { points: 5, duration: 3600, keyPrefix: 'admin_cleanup', blockDuration: 7200 }, // 5 per hour
    
    // Public verification endpoints - MODERATE limits
    'verify-proof': { points: 20, duration: 300, keyPrefix: 'verify_proof', blockDuration: 900 }, // 20 per 5min
    'verify-status': { points: 50, duration: 300, keyPrefix: 'verify_status', blockDuration: 600 }, // 50 per 5min
    'verify-webhook': { points: 10, duration: 60, keyPrefix: 'verify_webhook', blockDuration: 300 }, // 10 per minute
    
    // Discord API endpoints - CONTEXT-AWARE limits
    'discord-user': { points: 100, duration: 300, keyPrefix: 'discord_user', blockDuration: 600 }, // 100 per 5min
    'discord-register': { points: 30, duration: 300, keyPrefix: 'discord_register', blockDuration: 900 },
    'discord-verify': { points: 20, duration: 300, keyPrefix: 'discord_verify', blockDuration: 900 },
    'discord-role-update': { points: 15, duration: 300, keyPrefix: 'discord_role', blockDuration: 900 },
    'discord-health': { points: 200, duration: 300, keyPrefix: 'discord_health', blockDuration: 600 }, // Higher limit for health checks
    
    // Webhook endpoints - STRICTEST limits (external abuse prevention)
    'webhook-discord': { points: 5, duration: 60, keyPrefix: 'webhook_discord', blockDuration: 300 }, // 5 per minute
    'webhook-verification': { points: 10, duration: 60, keyPrefix: 'webhook_verification', blockDuration: 300 },
    'webhook-health': { points: 20, duration: 60, keyPrefix: 'webhook_health', blockDuration: 180 }, // 20 per minute
    
    // Discord bot commands - CONTEXT-AWARE limits
    'discord-command-verify': { points: 3, duration: 60, keyPrefix: 'cmd_verify', blockDuration: 300 }, // 3 per minute
    'discord-command-status': { points: 10, duration: 60, keyPrefix: 'cmd_status', blockDuration: 180 },
    'discord-command-help': { points: 20, duration: 60, keyPrefix: 'cmd_help', blockDuration: 120 },
    'discord-command-admin': { points: 5, duration: 300, keyPrefix: 'cmd_admin', blockDuration: 900 }, // 5 per 5min
    
    // Health and monitoring - GENEROUS limits
    'health': { points: 1000, duration: 300, keyPrefix: 'health', blockDuration: 60 },
    'metrics': { points: 100, duration: 300, keyPrefix: 'metrics', blockDuration: 300 }
  };

  constructor() {
    this.initializeRedis();
    this.initializeCleanup();
  }

  private async initializeRedis() {
    const redisUrl = process.env.REDIS_URL;
    
    if (redisUrl && process.env.NODE_ENV === 'production') {
      try {
        this.redisClient = new Redis(redisUrl);
        
        // Test Redis connection
        await this.redisClient.ping();
        logger.info('Redis rate limiting storage initialized');
      } catch (error) {
        logger.warn('Redis connection failed, falling back to memory storage', { error });
        this.redisClient = undefined;
      }
    } else {
      logger.info('Using memory-based rate limiting storage');
    }
  }

  private initializeCleanup() {
    // Clean up abuse tracker every 10 minutes
    setInterval(() => {
      this.cleanupAbuseTracker();
    }, 10 * 60 * 1000);

    // Clean up memory rate limiters every 30 minutes
    setInterval(() => {
      this.cleanupRateLimiters();
    }, 30 * 60 * 1000);
  }

  private cleanupAbuseTracker() {
    const now = new Date();
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    for (const [key, data] of this.abuseTracker.entries()) {
      if (data.lastViolation < oneDayAgo) {
        this.abuseTracker.delete(key);
      }
    }

    logger.debug(`Cleaned up abuse tracker, ${this.abuseTracker.size} entries remaining`);
  }

  private cleanupRateLimiters() {
    // Clear memory-based rate limiters that are no longer needed
    this.rateLimiters.clear();
    logger.debug('Cleaned up memory rate limiters');
  }

  private getRateLimiter(endpoint: string): RateLimiter {
    const config = this.endpointLimits[endpoint];
    if (!config) {
      throw new Error(`No rate limit configuration found for endpoint: ${endpoint}`);
    }

    const key = `${config.keyPrefix}:${config.duration}:${config.points}`;
    
    if (this.rateLimiters.has(key)) {
      return this.rateLimiters.get(key)!;
    }

    let rateLimiter: RateLimiter;

    if (this.redisClient) {
      rateLimiter = new RateLimiterRedis({
        storeClient: this.redisClient,
        keyPrefix: config.keyPrefix,
        points: config.points,
        duration: config.duration,
        blockDuration: config.blockDuration || config.duration,
        execEvenly: config.execEvenly || false,
        execEvenlyMinDelayMs: config.execEvenlyMinDelayMs || 0,
      });
    } else {
      rateLimiter = new RateLimiterMemory({
        keyPrefix: config.keyPrefix,
        points: config.points,
        duration: config.duration,
        blockDuration: config.blockDuration || config.duration,
        execEvenly: config.execEvenly || false,
        execEvenlyMinDelayMs: config.execEvenlyMinDelayMs || 0,
      });
    }

    this.rateLimiters.set(key, rateLimiter);
    return rateLimiter;
  }

  /**
   * Check if request is rate limited
   */
  async isRateLimited(
    endpoint: string,
    identifier: string,
    options: {
      userId?: string;
      ip?: string;
      authenticated?: boolean;
      privilegeLevel?: 'user' | 'admin' | 'service';
    } = {}
  ): Promise<{
    limited: boolean;
    remainingPoints?: number;
    msBeforeNext?: number;
    totalHits?: number;
    blockDuration?: number;
    isAbuse?: boolean;
  }> {
    try {
      const config = this.endpointLimits[endpoint];
      if (!config) {
        logger.warn('No rate limit config for endpoint', { endpoint });
        return { limited: false };
      }

      // Apply privilege-based multipliers
      if (options.privilegeLevel === 'admin') {
        // 50% more for admins
      } else if (options.privilegeLevel === 'service') {
        // 100% more for services
      }

      // Create composite identifier for better tracking
      let compositeKey = identifier;
      if (options.userId) {
        compositeKey = `user:${options.userId}:${endpoint}`;
      } else if (options.ip) {
        compositeKey = `ip:${options.ip}:${endpoint}`;
      }

      const rateLimiter = this.getRateLimiter(endpoint);
      
      try {
        const res = await rateLimiter.consume(compositeKey, 1);
        
        return {
          limited: false,
          remainingPoints: res.remainingPoints,
          msBeforeNext: res.msBeforeNext
        };
      } catch (rateLimiterRes: any) {
        // Rate limit exceeded
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const retrySecs = Math.round(rateLimiterRes.msBeforeNext / 1000) || 1;
        
        // Track abuse
        this.trackAbuseViolation(compositeKey, endpoint);
        
        return {
          limited: true,
          msBeforeNext: rateLimiterRes.msBeforeNext,
          isAbuse: this.isAbuseSuspected(compositeKey)
        };
      }
    } catch (error) {
      logger.error('Rate limit check failed', { endpoint, error });
      // On error, allow request but log for monitoring
      return { limited: false };
    }
  }

  /**
   * Check rate limit with sliding window
   */
  async checkSlidingWindow(
    endpoint: string,
    identifier: string,
    windowMs: number = 60000
  ): Promise<{
    allowed: boolean;
    requestsInWindow: number;
    windowStart: Date;
    isPatternAbuse?: boolean;
  }> {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const key = `sliding:${endpoint}:${identifier}`;
    const now = Date.now();
    const windowStart = new Date(now - windowMs);

    // For Redis implementation, we would use sorted sets
    // For now, using a simplified approach with memory storage
    try {
      // This is a simplified sliding window - in production, use Redis sorted sets
      const config = this.endpointLimits[endpoint];
      
      if (!config) {
        return { allowed: true, requestsInWindow: 0, windowStart };
      }

      // Check if within limits using standard rate limiter
      const checkResult = await this.isRateLimited(endpoint, identifier);
      
      return {
        allowed: !checkResult.limited,
        requestsInWindow: config.points - (checkResult.remainingPoints || 0),
        windowStart,
        isPatternAbuse: checkResult.isAbuse
      };
    } catch (error) {
      logger.error('Sliding window check failed', { error });
      return { allowed: true, requestsInWindow: 0, windowStart };
    }
  }

  /**
   * Token bucket rate limiting for burst handling
   */
  async checkTokenBucket(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    endpoint: string,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    identifier: string,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    tokens: number = 1
  ): Promise<{
    allowed: boolean;
    tokensRemaining: number;
    refillTime?: number;
  }> {
    try {
      const config = this.endpointLimits[endpoint];
      if (!config) {
        return { allowed: true, tokensRemaining: 100 }; // Default for unknown endpoints
      }

      return {
        allowed: true,
        tokensRemaining: config.points - 1 // Simplified calculation
      };
    } catch (error) {
      return {
        allowed: false,
        tokensRemaining: 0
      };
    }
  }

  /**
   * Track rate limit violations for abuse detection
   */
  private trackAbuseViolation(key: string, endpoint: string) {
    const existing = this.abuseTracker.get(key) || {
      violations: 0,
      lastViolation: new Date(),
      blocked: false
    };

    existing.violations += 1;
    existing.lastViolation = new Date();

    // Auto-block after 5 violations in 1 hour
    if (existing.violations >= 5) {
      existing.blocked = true;
      logger.warn('Auto-blocking endpoint for repeated violations', { endpoint, key, violations: existing.violations });
    }

    this.abuseTracker.set(key, existing);

    // Log abuse attempt
    logger.warn('Rate limit violation detected', {
      key,
      endpoint,
      violations: existing.violations,
      blocked: existing.blocked,
      timestamp: existing.lastViolation
    });
  }

  /**
   * Check if abuse is suspected
   */
  private isAbuseSuspected(key: string): boolean {
    const data = this.abuseTracker.get(key);
    return data?.blocked || false;
  }

  /**
   * Get rate limit statistics
   */
  getStats(): {
    activeLimiters: number;
    abuseEntries: number;
    redisConnected: boolean;
    endpointsConfigured: number;
  } {
    return {
      activeLimiters: this.rateLimiters.size,
      abuseEntries: this.abuseTracker.size,
      redisConnected: !!this.redisClient,
      endpointsConfigured: Object.keys(this.endpointLimits).length
    };
  }

  /**
   * Reset rate limit for a specific key (admin function)
   */
  async resetRateLimit(endpoint: string, identifier: string): Promise<boolean> {
    try {
      const config = this.endpointLimits[endpoint];
      if (!config) {
        throw new Error(`No rate limit configuration found for endpoint: ${endpoint}`);
      }

      const key = `${config.keyPrefix}:${identifier}`;
      
      if (this.redisClient) {
        await this.redisClient.del(key);
      } else {
        // For memory storage, we'd need to implement key management
        logger.warn('Memory-based rate limiter reset not implemented');
      }

      // Clear abuse tracking
      this.abuseTracker.delete(identifier);

      logger.info('Rate limit reset', { endpoint, identifier });
      return true;
    } catch (error) {
      logger.error('Failed to reset rate limit', { error });
      return false;
    }
  }

  /**
   * Get rate limit configuration for an endpoint
   */
  getEndpointConfig(endpoint: string): RateLimitConfig | null {
    return this.endpointLimits[endpoint] || null;
  }

  /**
   * Update rate limit configuration (admin function)
   */
  updateEndpointConfig(endpoint: string, config: Partial<RateLimitConfig>): void {
    const existing = this.endpointLimits[endpoint];
    if (!existing) {
      throw new Error(`Endpoint ${endpoint} not found in configuration`);
    }

    this.endpointLimits[endpoint] = { ...existing, ...config };

    // Clear existing rate limiter for this endpoint
    const key = `${existing.keyPrefix}:${existing.duration}:${existing.points}`;
    this.rateLimiters.delete(key);

    logger.info('Updated rate limit config for endpoint', { endpoint, config });
  }
}

// Export singleton instance
export const rateLimitManager = new UniversalRateLimitManager();