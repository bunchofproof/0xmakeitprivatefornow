/**
 * Rate Limiting for Bot Service
 * Uses proper server-side RateLimiterMemory implementation
 */

import { RateLimiterMemory } from 'rate-limiter-flexible';
import { config } from '../config';

export class UniversalRateLimitManager {
  private rateLimiter: RateLimiterMemory;
  private abuseTracker = new Map<string, { violations: number; lastViolation: Date; blocked: boolean }>();

  constructor() {
    // Initialize the rate limiter with config values
    const opts = {
      points: config.rateLimit.command.points,
      duration: config.rateLimit.command.duration,
    };
    this.rateLimiter = new RateLimiterMemory(opts);

    this.initializeCleanup();
  }

  private initializeCleanup() {
    // Clean up abuse tracker every 10 minutes
    setInterval(() => {
      this.cleanupAbuseTracker();
    }, 10 * 60 * 1000);
  }

  private cleanupAbuseTracker() {
    const now = new Date();
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    for (const [key, data] of this.abuseTracker.entries()) {
      if (data.lastViolation < oneDayAgo) {
        this.abuseTracker.delete(key);
      }
    }

    console.log(`Bot rate limit: Cleaned up abuse tracker, ${this.abuseTracker.size} entries remaining`);
  }

  /**
   * Check if request is rate limited (legacy method)
   */
  async isRateLimitedLegacy(
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
      // Create composite identifier for better tracking
      let compositeKey = identifier;
      if (options.userId) {
        compositeKey = `user:${options.userId}:${endpoint}`;
      } else if (options.ip) {
        compositeKey = `ip:${options.ip}:${endpoint}`;
      }

      try {
        const res = await this.rateLimiter.consume(compositeKey, 1);

        return {
          limited: false,
          remainingPoints: res.remainingPoints,
          msBeforeNext: res.msBeforeNext
        };
      } catch (rateLimiterRes: any) {
        // Rate limit exceeded

        // Track abuse
        this.trackAbuseViolation(compositeKey, endpoint);

        return {
          limited: true,
          msBeforeNext: rateLimiterRes.msBeforeNext,
          isAbuse: this.isAbuseSuspected(compositeKey)
        };
      }
    } catch (error) {
      console.error(`Bot rate limit check failed for ${endpoint}:`, error);
      // On error, allow request but log it
      return { limited: false };
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
      console.warn(`Bot rate limit: Auto-blocking endpoint ${endpoint} for ${key} due to repeated violations`);
    }

    this.abuseTracker.set(key, existing);

    // Log abuse attempt
    console.warn(`Bot rate limit: Rate limit violation detected:`, {
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
      activeLimiters: 1, // Single rate limiter instance
      abuseEntries: this.abuseTracker.size,
      redisConnected: false, // Bot uses in-memory only
      endpointsConfigured: 1 // Single command rate limiter
    };
  }

  /**
   * Get rate limit configuration for an endpoint
   */
  getEndpointConfig(_endpoint: string): { points: number; duration: number } | null {
    // Return the single rate limit config for all endpoints
    return {
      points: config.rateLimit.command.points,
      duration: config.rateLimit.command.duration
    };
  }

  /**
   * Check if rate limited - simplified function for direct use
   */
  async isRateLimited(key: string): Promise<boolean> {
    try {
      await this.rateLimiter.consume(key);
      return false; // Not rate limited
    } catch (error) {
      return true; // Is rate limited
    }
  }
}

// Export singleton instance
export const rateLimitManager = new UniversalRateLimitManager();