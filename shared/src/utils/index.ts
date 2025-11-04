// Shared utilities for ZKPassport Discord verification system

import { randomBytes } from 'crypto';

/**
 * Generates a cryptographically secure random token
 */
export function generateSecureToken(length: number = 32): string {
  return randomBytes(length).toString('hex');
}

/**
 * Generates a random string of specified length using alphanumeric characters
 */
export function generateRandomString(length: number = 16): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

/**
 * Validates if a Discord user ID is in the correct format (18-19 digit number)
 */
export function isValidDiscordUserId(userId: string): boolean {
  return /^\d{17,19}$/.test(userId);
}

/**
 * Validates if a Discord snowflake ID is valid
 */
export function isValidSnowflake(id: string): boolean {
  const num = parseInt(id);
  return !isNaN(num) && num > 0 && id.length >= 17 && id.length <= 19;
}

/**
 * Formats a timestamp for display
 */
export function formatTimestamp(date: Date): string {
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short'
  });
}

/**
 * Calculates days until expiration
 */
export function daysUntilExpiration(expiresAt: Date): number {
  const now = new Date();
  const diffTime = expiresAt.getTime() - now.getTime();
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  return diffDays;
}

/**
 * Checks if a verification has expired
 */
export function isExpired(expiresAt: Date): boolean {
  return new Date() > expiresAt;
}

/**
 * Sanitizes user input to prevent injection attacks
 */
export function sanitizeInput(input: string): string {
  return input.replace(/[<>]/g, '').trim();
}

/**
 * Truncates a string to specified length with ellipsis
 */
export function truncateString(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.substring(0, maxLength - 3) + '...';
}

/**
 * Creates a safe error message that doesn't leak sensitive information
 */
export function createSafeErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return 'An error occurred during verification. Please try again.';
  }
  return 'An unexpected error occurred. Please contact an administrator.';
}

/**
 * Validates environment variables are present
 */
export function validateEnvironment(env: Record<string, string | undefined>): void {
  const missing: string[] = [];

  for (const [key, value] of Object.entries(env)) {
    if (value === undefined || value === '') {
      missing.push(key);
    }
  }

  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}

/**
 * Sleep utility for delays
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Rate limiting utility
 */
export class RateLimiter {
  protected attempts = new Map<string, { count: number; resetTime: number }>();

  constructor(
    private maxAttempts: number = 5,
    private windowMs: number = 60000 // 1 minute
  ) {}

  isAllowed(key: string): boolean {
    const now = Date.now();
    const record = this.attempts.get(key);

    if (!record || now > record.resetTime) {
      this.attempts.set(key, { count: 1, resetTime: now + this.windowMs });
      return true;
    }

    if (record.count >= this.maxAttempts) {
      return false;
    }

    record.count++;
    return true;
  }

  reset(key: string): void {
    this.attempts.delete(key);
  }

  getRemainingTime(key: string): number {
    const record = this.attempts.get(key);
    if (!record) return 0;

    const remaining = record.resetTime - Date.now();
    return Math.max(0, remaining);
  }
}

/**
 * Simple cache implementation
 */
export class SimpleCache<T> {
  private cache = new Map<string, { value: T; expiry: number }>();

  constructor(private defaultTTL: number = 300000) {} // 5 minutes default

  set(key: string, value: T, ttl?: number): void {
    const expiry = Date.now() + (ttl || this.defaultTTL);
    this.cache.set(key, { value, expiry });
  }

  get(key: string): T | null {
    const record = this.cache.get(key);
    if (!record) return null;

    if (Date.now() > record.expiry) {
      this.cache.delete(key);
      return null;
    }

    return record.value;
  }

  delete(key: string): void {
    this.cache.delete(key);
  }

  clear(): void {
    this.cache.clear();
  }
}

// Web-specific utilities for ZKPassport integration

/**
 * Validates a verification token format
 */
export function isValidVerificationToken(token: string): boolean {
  // Tokens should be alphanumeric and at least 10 characters
  return /^[a-zA-Z0-9]{10,}$/.test(token);
}

/**
 * Sanitizes URL parameters to prevent injection attacks
 */
export function sanitizeUrlParameter(param: string): string {
  return param.replace(/[<>\"'&]/g, '').trim();
}

/**
 * Creates a safe redirect URL
 */
export function createSafeRedirectUrl(baseUrl: string, path: string): string {
  try {
    const url = new URL(path, baseUrl);
    // Only allow relative paths or same origin
    if (url.origin === baseUrl) {
      return url.pathname + url.search;
    }
    return '/';
  } catch {
    return '/';
  }
}

/**
 * Validates ZKPassport proof structure
 */
export function isValidZKPassportProof(proof: any): boolean {
  if (!proof || typeof proof !== 'object') {
    return false;
  }

  // Basic structure validation - adjust based on actual ZKPassport proof format
  return (
    proof.proof !== undefined &&
    proof.inputs !== undefined &&
    Array.isArray(proof.inputs)
  );
}

/**
 * Creates a CORS-safe origin checker
 */
export function createOriginChecker(allowedOrigins: string[]) {
  return function isOriginAllowed(origin: string | null): boolean {
    if (!origin) return false;

    // Allow localhost for development
    if (process.env.NODE_ENV !== 'production') {
      if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
        return true;
      }
    }

    return allowedOrigins.includes(origin);
  };
}

/**
 * Rate limiter for web requests
 */
export class WebRateLimiter extends RateLimiter {
  constructor(
    maxAttempts: number = 100,
    windowMs: number = 15 * 60 * 1000 // 15 minutes
  ) {
    super(maxAttempts, windowMs);
  }

  getRemainingTime(key: string): number {
    const record = this.attempts.get(key);
    if (!record) return 0;

    const remaining = record.resetTime - Date.now();
    return Math.max(0, remaining);
  }
}

/**
 * Security utilities for web requests
 */
export class WebSecurity {
  static sanitizeRequestBody(body: any): any {
    if (typeof body === 'string') {
      return sanitizeInput(body);
    }

    if (typeof body === 'object' && body !== null) {
      const sanitized: any = {};
      for (const [key, value] of Object.entries(body)) {
        if (typeof value === 'string') {
          sanitized[key] = sanitizeInput(value);
        } else if (typeof value === 'object' && value !== null) {
          sanitized[key] = this.sanitizeRequestBody(value);
        } else {
          sanitized[key] = value;
        }
      }
      return sanitized;
    }

    return body;
  }

  static validateContentType(contentType: string | null): boolean {
    const allowedTypes = [
      'application/json',
      'application/x-www-form-urlencoded',
    ];

    return contentType ? allowedTypes.includes(contentType) : false;
  }

  static isValidUserAgent(userAgent: string): boolean {
    // Basic bot detection - can be enhanced
    const botPatterns = [
      /bot/i,
      /spider/i,
      /crawler/i,
      /scraper/i,
    ];

    return !botPatterns.some(pattern => pattern.test(userAgent));
  }
}

/**
 * ZKPassport-specific utilities
 */
export class ZKPassportUtils {
  static createVerificationRequest(_domain: string, purpose: string) {
    return {
      name: "Discord Admin Verification",
      logo: "https://zkpassport.id/favicon.png",
      purpose,
      scope: "adult",
      mode: "compressed-evm",
      devMode: process.env.NODE_ENV !== "production",
    };
  }

  static validateVerificationResponse(response: any): boolean {
    return (
      response &&
      typeof response === 'object' &&
      typeof response.verified === 'boolean' &&
      (response.uniqueIdentifier === undefined || typeof response.uniqueIdentifier === 'string')
    );
  }

  static formatUniqueIdentifier(identifier: string): string {
    if (identifier.length <= 16) return identifier;
    return `${identifier.substring(0, 8)}...${identifier.substring(identifier.length - 8)}`;
  }
}

// Export database concurrency control utilities
export { DatabaseLockManager, LockType } from './databaseLockManager';