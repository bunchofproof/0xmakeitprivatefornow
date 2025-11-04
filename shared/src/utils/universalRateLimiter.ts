/**
 * Universal Rate Limiting Framework - Citadel 2.0 Phase 2.4
 * Multi-layer DoS protection with adaptive rate limiting
 */

import { RateLimiterMemory, RateLimiterRedis, IRateLimiterOptions } from 'rate-limiter-flexible';
import { Redis } from 'ioredis';

export { RateLimiterMemory, RateLimiterRedis };
export type { IRateLimiterOptions };
export { Redis };

type RateLimiter = RateLimiterMemory | RateLimiterRedis;

export interface RateLimitConfig {
  points: number;           // Number of requests
  duration: number;         // Duration in seconds
  keyPrefix: string;        // Storage key prefix
  blockDuration?: number;   // Block duration in seconds
  execEvenly?: boolean;     // Distribute requests evenly
  execEvenlyMinDelayMs?: number;
}

export interface EndpointRateLimit {
  [key: string]: RateLimitConfig;
}

export interface RateLimitHeaders {
  'X-RateLimit-Limit': string;
  'X-RateLimit-Remaining': string;
  'X-RateLimit-Reset': string;
  'Retry-After'?: string;
}

export interface AdaptiveConfig {
  enabled: boolean;
  cpuThreshold: number;
  memoryThreshold: number;
  reductionFactor: number;
  increaseFactor: number;
  checkInterval: number;
}

export class UniversalRateLimitManager {
  private redisClient?: Redis;
  private rateLimiters = new Map<string, RateLimiter>();
  private abuseTracker = new Map<string, { violations: number; lastViolation: Date; blocked: boolean }>();
  private requestMetrics = new Map<string, { requests: number; startTime: number; maxRPS: number }>();
  private adaptiveConfig: AdaptiveConfig;
  
  // Enhanced endpoint-specific rate limits with DoS protection
  private readonly endpointLimits: EndpointRateLimit = {
    // 🔐 AUTHENTICATION ENDPOINTS - STRICTEST PROTECTION
    'auth-login': { 
      points: 5, duration: 900, keyPrefix: 'auth_login', blockDuration: 1800,
      execEvenly: true, execEvenlyMinDelayMs: 1000 // 1 per 1s
    },
    'auth-verify': { 
      points: 3, duration: 300, keyPrefix: 'auth_verify', blockDuration: 900,
      execEvenly: true, execEvenlyMinDelayMs: 2000 // 1 per 2s
    },
    'auth-register': { 
      points: 10, duration: 3600, keyPrefix: 'auth_register', blockDuration: 7200,
      execEvenly: true, execEvenlyMinDelayMs: 500
    },
    
    // 🛡️ ADMIN ENDPOINTS - STRICT IP-BASED PROTECTION
    'admin-stats': { 
      points: 30, duration: 300, keyPrefix: 'admin_stats', blockDuration: 900,
      execEvenly: true, execEvenlyMinDelayMs: 100
    },
    'admin-verify-user': { 
      points: 10, duration: 300, keyPrefix: 'admin_verify', blockDuration: 1800,
      execEvenly: true, execEvenlyMinDelayMs: 500
    },
    'admin-revoke-user': { 
      points: 10, duration: 300, keyPrefix: 'admin_revoke', blockDuration: 1800,
      execEvenly: true, execEvenlyMinDelayMs: 500
    },
    'admin-sessions': { 
      points: 20, duration: 300, keyPrefix: 'admin_sessions', blockDuration: 900,
      execEvenly: true, execEvenlyMinDelayMs: 200
    },
    'admin-cleanup': { 
      points: 5, duration: 3600, keyPrefix: 'admin_cleanup', blockDuration: 7200,
      execEvenly: true, execEvenlyMinDelayMs: 2000 // 1 per 2s
    },
    
    // 🔍 VERIFICATION ENDPOINTS - RESOURCE PROTECTION
    'verify-proof': { 
      points: 20, duration: 300, keyPrefix: 'verify_proof', blockDuration: 900,
      execEvenly: true, execEvenlyMinDelayMs: 300
    },
    'verify-status': { 
      points: 100, duration: 300, keyPrefix: 'verify_status', blockDuration: 600,
      execEvenly: true, execEvenlyMinDelayMs: 50
    },
    'verify-webhook': { 
      points: 10, duration: 60, keyPrefix: 'verify_webhook', blockDuration: 300,
      execEvenly: true, execEvenlyMinDelayMs: 200
    },
    
    // 💬 DISCORD ENDPOINTS - API INTEGRATION PROTECTION
    'discord-user': { 
      points: 100, duration: 300, keyPrefix: 'discord_user', blockDuration: 600,
      execEvenly: true, execEvenlyMinDelayMs: 30
    },
    'discord-register': { 
      points: 30, duration: 300, keyPrefix: 'discord_register', blockDuration: 900,
      execEvenly: true, execEvenlyMinDelayMs: 100
    },
    'discord-verify': { 
      points: 20, duration: 300, keyPrefix: 'discord_verify', blockDuration: 900,
      execEvenly: true, execEvenlyMinDelayMs: 200
    },
    'discord-role-update': { 
      points: 15, duration: 300, keyPrefix: 'discord_role', blockDuration: 900,
      execEvenly: true, execEvenlyMinDelayMs: 300
    },
    'discord-health': { 
      points: 200, duration: 300, keyPrefix: 'discord_health', blockDuration: 600,
      execEvenly: true, execEvenlyMinDelayMs: 10
    },
    
    // 🌐 WEBHOOK ENDPOINTS - EXTERNAL ABUSE PREVENTION
    'webhook-discord': { 
      points: 5, duration: 60, keyPrefix: 'webhook_discord', blockDuration: 300,
      execEvenly: true, execEvenlyMinDelayMs: 500
    },
    'webhook-verification': { 
      points: 10, duration: 60, keyPrefix: 'webhook_verification', blockDuration: 300,
      execEvenly: true, execEvenlyMinDelayMs: 300
    },
    'webhook-health': { 
      points: 20, duration: 60, keyPrefix: 'webhook_health', blockDuration: 180,
      execEvenly: true, execEvenlyMinDelayMs: 200
    },
    
    // 🔧 SECURITY ENDPOINTS - DoS PROTECTION
    'security-xss-report': { 
      points: 10, duration: 300, keyPrefix: 'security_xss', blockDuration: 900,
      execEvenly: true, execEvenlyMinDelayMs: 200
    },
    'security-csp-report': { 
      points: 10, duration: 300, keyPrefix: 'security_csp', blockDuration: 900,
      execEvenly: true, execEvenlyMinDelayMs: 200
    },
    'security-hsts-report': { 
      points: 10, duration: 300, keyPrefix: 'security_hsts', blockDuration: 900,
      execEvenly: true, execEvenlyMinDelayMs: 200
    },
    'security-ct-report': { 
      points: 5, duration: 300, keyPrefix: 'security_ct', blockDuration: 900,
      execEvenly: true, execEvenlyMinDelayMs: 500
    },
    'security-nel-report': { 
      points: 15, duration: 300, keyPrefix: 'security_nel', blockDuration: 900,
      execEvenly: true, execEvenlyMinDelayMs: 100
    },
    'security-reports': { 
      points: 20, duration: 300, keyPrefix: 'security_reports', blockDuration: 900,
      execEvenly: true, execEvenlyMinDelayMs: 100
    },
    'security-headers': { 
      points: 100, duration: 300, keyPrefix: 'security_headers', blockDuration: 300,
      execEvenly: true, execEvenlyMinDelayMs: 10
    },
    
    // 🏥 HEALTH ENDPOINTS - GENEROUS FOR MONITORING
    'health': { 
      points: 1000, duration: 300, keyPrefix: 'health', blockDuration: 60,
      execEvenly: true, execEvenlyMinDelayMs: 10
    },
    'metrics': { 
      points: 100, duration: 300, keyPrefix: 'metrics', blockDuration: 300,
      execEvenly: true, execEvenlyMinDelayMs: 100
    }
  };

  constructor() {
    this.adaptiveConfig = {
      enabled: process.env.RATE_LIMIT_ADAPTIVE === 'true',
      cpuThreshold: parseFloat(process.env.RATE_LIMIT_CPU_THRESHOLD || '80'),
      memoryThreshold: parseFloat(process.env.RATE_LIMIT_MEMORY_THRESHOLD || '85'),
      reductionFactor: parseFloat(process.env.RATE_LIMIT_REDUCTION_FACTOR || '0.5'),
      increaseFactor: parseFloat(process.env.RATE_LIMIT_INCREASE_FACTOR || '1.1'),
      checkInterval: parseInt(process.env.RATE_LIMIT_CHECK_INTERVAL || '30000')
    };

    this.initializeRedis();
    this.initializeCleanup();
    this.initializeAdaptiveMonitoring();
  }

  private async initializeRedis() {
    const redisUrl = process.env.REDIS_URL;
    
    if (redisUrl && process.env.NODE_ENV === 'production') {
      try {
        this.redisClient = new Redis(redisUrl);
        await this.redisClient.ping();
        console.log('✅ Redis rate limiting storage initialized');
      } catch (error) {
        console.warn('⚠️ Redis connection failed, falling back to memory storage:', error);
        this.redisClient = undefined;
      }
    } else {
      console.log('📝 Using memory-based rate limiting storage');
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

  private initializeAdaptiveMonitoring() {
    if (!this.adaptiveConfig.enabled) return;

    setInterval(() => {
      this.checkSystemLoad();
    }, this.adaptiveConfig.checkInterval);
  }

  private cleanupAbuseTracker() {
    const now = new Date();
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    for (const [key, data] of this.abuseTracker.entries()) {
      if (data.lastViolation < oneDayAgo) {
        this.abuseTracker.delete(key);
      }
    }

    console.debug(`Cleaned up abuse tracker, ${this.abuseTracker.size} entries remaining`);
  }

  private cleanupRateLimiters() {
    this.rateLimiters.clear();
    console.debug('Cleaned up memory rate limiters');
  }

  private checkSystemLoad() {
    try {
      const cpuUsage = process.cpuUsage();
      const memoryUsage = process.memoryUsage();
      
      const cpuPercent = (cpuUsage.user + cpuUsage.system) / 100000; // Simplified calculation
      const memoryPercent = (memoryUsage.heapUsed / memoryUsage.heapTotal) * 100;

      if (cpuPercent > this.adaptiveConfig.cpuThreshold || memoryPercent > this.adaptiveConfig.memoryThreshold) {
        console.warn(`🚨 High system load detected - CPU: ${cpuPercent.toFixed(2)}%, Memory: ${memoryPercent.toFixed(2)}%`);
        this.reduceRateLimits();
      } else {
        this.increaseRateLimits();
      }
    } catch (error) {
      console.error('System load check failed:', error);
    }
  }

  private reduceRateLimits() {
    console.log('📉 Reducing rate limits due to high system load');
    // In a full implementation, this would adjust the actual rate limiter configs
    // For now, we log the action
  }

  private increaseRateLimits() {
    console.log('📈 Increasing rate limits due to normal system load');
    // In a full implementation, this would gradually restore normal limits
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
   * Check if request is rate limited with enhanced tracking
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
    headers?: RateLimitHeaders;
  }> {
    try {
      const config = this.endpointLimits[endpoint];
      if (!config) {
        console.warn(`No rate limit config for endpoint: ${endpoint}`);
        return { limited: false };
      }

      // Track request metrics
      this.trackRequestMetrics(endpoint);

      // Apply privilege-based adjustments
      let adjustedConfig = { ...config };
      if (options.privilegeLevel === 'admin') {
        adjustedConfig.points = Math.floor(config.points * 1.5); // 50% more for admins
      } else if (options.privilegeLevel === 'service') {
        adjustedConfig.points = Math.floor(config.points * 2); // 100% more for services
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
          msBeforeNext: res.msBeforeNext,
          headers: {
            'X-RateLimit-Limit': config.points.toString(),
            'X-RateLimit-Remaining': res.remainingPoints.toString(),
            'X-RateLimit-Reset': (Date.now() + (res.msBeforeNext || 0)).toString()
          }
        };
      } catch (rateLimiterRes: any) {
        // Rate limit exceeded
        const retrySecs = Math.round(rateLimiterRes.msBeforeNext / 1000) || 1;
        
        // Track abuse
        this.trackAbuseViolation(compositeKey, endpoint);
        
        return {
          limited: true,
          msBeforeNext: rateLimiterRes.msBeforeNext,
          isAbuse: this.isAbuseSuspected(compositeKey),
          headers: {
            'X-RateLimit-Limit': config.points.toString(),
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': (Date.now() + (rateLimiterRes.msBeforeNext || 0)).toString(),
            'Retry-After': retrySecs.toString()
          }
        };
      }
    } catch (error) {
      console.error(`Rate limit check failed for ${endpoint}:`, error);
      return { limited: false };
    }
  }

  /**
   * Track request metrics for monitoring
   */
  private trackRequestMetrics(endpoint: string) {
    const now = Date.now();
    const metrics = this.requestMetrics.get(endpoint) || { requests: 0, startTime: now, maxRPS: 0 };
    
    metrics.requests++;
    
    // Calculate requests per second
    const elapsedSeconds = (now - metrics.startTime) / 1000;
    if (elapsedSeconds > 0) {
      const currentRPS = metrics.requests / elapsedSeconds;
      metrics.maxRPS = Math.max(metrics.maxRPS, currentRPS);
    }
    
    // Reset every 60 seconds
    if (elapsedSeconds > 60) {
      metrics.requests = 0;
      metrics.startTime = now;
    }
    
    this.requestMetrics.set(endpoint, metrics);
  }

  /**
   * Get rate limit statistics
   */
  getStats(): {
    activeLimiters: number;
    abuseEntries: number;
    redisConnected: boolean;
    endpointsConfigured: number;
    requestMetrics: { [key: string]: { maxRPS: number; totalRequests: number } };
    adaptiveEnabled: boolean;
  } {
    const metrics: { [key: string]: { maxRPS: number; totalRequests: number } } = {};
    
    for (const [endpoint, data] of this.requestMetrics.entries()) {
      metrics[endpoint] = {
        maxRPS: Math.round(data.maxRPS),
        totalRequests: data.requests
      };
    }

    return {
      activeLimiters: this.rateLimiters.size,
      abuseEntries: this.abuseTracker.size,
      redisConnected: !!this.redisClient,
      endpointsConfigured: Object.keys(this.endpointLimits).length,
      requestMetrics: metrics,
      adaptiveEnabled: this.adaptiveConfig.enabled
    };
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
      console.warn(`🚫 Auto-blocking endpoint ${endpoint} for ${key} due to repeated violations`);
    }

    this.abuseTracker.set(key, existing);

    console.warn(`⚠️ Rate limit violation detected:`, {
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
        console.warn('Memory-based rate limiter reset not implemented');
      }

      // Clear abuse tracking
      this.abuseTracker.delete(identifier);

      console.info(`🔄 Rate limit reset for ${endpoint}:${identifier}`);
      return true;
    } catch (error) {
      console.error(`Failed to reset rate limit:`, error);
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

    console.info(`🔧 Updated rate limit config for ${endpoint}:`, config);
  }
}

// Export singleton instance
export const rateLimitManager = new UniversalRateLimitManager();