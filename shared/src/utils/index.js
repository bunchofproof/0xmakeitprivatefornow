"use strict";
// Shared utilities for ZKPassport Discord verification system
Object.defineProperty(exports, "__esModule", { value: true });
exports.ZKPassportUtils = exports.WebSecurity = exports.WebRateLimiter = exports.SimpleCache = exports.RateLimiter = void 0;
exports.generateSecureToken = generateSecureToken;
exports.generateRandomString = generateRandomString;
exports.isValidDiscordUserId = isValidDiscordUserId;
exports.isValidSnowflake = isValidSnowflake;
exports.formatTimestamp = formatTimestamp;
exports.daysUntilExpiration = daysUntilExpiration;
exports.isExpired = isExpired;
exports.sanitizeInput = sanitizeInput;
exports.truncateString = truncateString;
exports.createSafeErrorMessage = createSafeErrorMessage;
exports.validateEnvironment = validateEnvironment;
exports.sleep = sleep;
exports.isValidVerificationToken = isValidVerificationToken;
exports.sanitizeUrlParameter = sanitizeUrlParameter;
exports.createSafeRedirectUrl = createSafeRedirectUrl;
exports.isValidZKPassportProof = isValidZKPassportProof;
exports.createOriginChecker = createOriginChecker;
const crypto_1 = require("crypto");
/**
 * Generates a cryptographically secure random token
 */
function generateSecureToken(length = 32) {
    return (0, crypto_1.randomBytes)(length).toString('hex');
}
/**
 * Generates a random string of specified length using alphanumeric characters
 */
function generateRandomString(length = 16) {
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
function isValidDiscordUserId(userId) {
    return /^\d{17,19}$/.test(userId);
}
/**
 * Validates if a Discord snowflake ID is valid
 */
function isValidSnowflake(id) {
    const num = parseInt(id);
    return !isNaN(num) && num > 0 && id.length >= 17 && id.length <= 19;
}
/**
 * Formats a timestamp for display
 */
function formatTimestamp(date) {
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
function daysUntilExpiration(expiresAt) {
    const now = new Date();
    const diffTime = expiresAt.getTime() - now.getTime();
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
}
/**
 * Checks if a verification has expired
 */
function isExpired(expiresAt) {
    return new Date() > expiresAt;
}
/**
 * Sanitizes user input to prevent injection attacks
 */
function sanitizeInput(input) {
    return input.replace(/[<>]/g, '').trim();
}
/**
 * Truncates a string to specified length with ellipsis
 */
function truncateString(str, maxLength) {
    if (str.length <= maxLength)
        return str;
    return str.substring(0, maxLength - 3) + '...';
}
/**
 * Creates a safe error message that doesn't leak sensitive information
 */
function createSafeErrorMessage(error) {
    if (error instanceof Error) {
        return 'An error occurred during verification. Please try again.';
    }
    return 'An unexpected error occurred. Please contact an administrator.';
}
/**
 * Validates environment variables are present
 */
function validateEnvironment(env) {
    const missing = [];
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
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
/**
 * Rate limiting utility
 */
class RateLimiter {
    maxAttempts;
    windowMs;
    attempts = new Map();
    constructor(maxAttempts = 5, windowMs = 60000 // 1 minute
    ) {
        this.maxAttempts = maxAttempts;
        this.windowMs = windowMs;
    }
    isAllowed(key) {
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
    reset(key) {
        this.attempts.delete(key);
    }
    getRemainingTime(key) {
        const record = this.attempts.get(key);
        if (!record)
            return 0;
        const remaining = record.resetTime - Date.now();
        return Math.max(0, remaining);
    }
}
exports.RateLimiter = RateLimiter;
/**
 * Simple cache implementation
 */
class SimpleCache {
    defaultTTL;
    cache = new Map();
    constructor(defaultTTL = 300000) {
        this.defaultTTL = defaultTTL;
    } // 5 minutes default
    set(key, value, ttl) {
        const expiry = Date.now() + (ttl || this.defaultTTL);
        this.cache.set(key, { value, expiry });
    }
    get(key) {
        const record = this.cache.get(key);
        if (!record)
            return null;
        if (Date.now() > record.expiry) {
            this.cache.delete(key);
            return null;
        }
        return record.value;
    }
    delete(key) {
        this.cache.delete(key);
    }
    clear() {
        this.cache.clear();
    }
}
exports.SimpleCache = SimpleCache;
// Web-specific utilities for ZKPassport integration
/**
 * Validates a verification token format
 */
function isValidVerificationToken(token) {
    // Tokens should be alphanumeric and at least 10 characters
    return /^[a-zA-Z0-9]{10,}$/.test(token);
}
/**
 * Sanitizes URL parameters to prevent injection attacks
 */
function sanitizeUrlParameter(param) {
    return param.replace(/[<>\"'&]/g, '').trim();
}
/**
 * Creates a safe redirect URL
 */
function createSafeRedirectUrl(baseUrl, path) {
    try {
        const url = new URL(path, baseUrl);
        // Only allow relative paths or same origin
        if (url.origin === baseUrl) {
            return url.pathname + url.search;
        }
        return '/';
    }
    catch {
        return '/';
    }
}
/**
 * Validates ZKPassport proof structure
 */
function isValidZKPassportProof(proof) {
    if (!proof || typeof proof !== 'object') {
        return false;
    }
    // Basic structure validation - adjust based on actual ZKPassport proof format
    return (proof.proof !== undefined &&
        proof.inputs !== undefined &&
        Array.isArray(proof.inputs));
}
/**
 * Creates a CORS-safe origin checker
 */
function createOriginChecker(allowedOrigins) {
    return function isOriginAllowed(origin) {
        if (!origin)
            return false;
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
class WebRateLimiter extends RateLimiter {
    constructor(maxAttempts = 100, windowMs = 15 * 60 * 1000 // 15 minutes
    ) {
        super(maxAttempts, windowMs);
    }
    getRemainingTime(key) {
        const record = this.attempts.get(key);
        if (!record)
            return 0;
        const remaining = record.resetTime - Date.now();
        return Math.max(0, remaining);
    }
}
exports.WebRateLimiter = WebRateLimiter;
/**
 * Security utilities for web requests
 */
class WebSecurity {
    static sanitizeRequestBody(body) {
        if (typeof body === 'string') {
            return sanitizeInput(body);
        }
        if (typeof body === 'object' && body !== null) {
            const sanitized = {};
            for (const [key, value] of Object.entries(body)) {
                if (typeof value === 'string') {
                    sanitized[key] = sanitizeInput(value);
                }
                else if (typeof value === 'object' && value !== null) {
                    sanitized[key] = this.sanitizeRequestBody(value);
                }
                else {
                    sanitized[key] = value;
                }
            }
            return sanitized;
        }
        return body;
    }
    static validateContentType(contentType) {
        const allowedTypes = [
            'application/json',
            'application/x-www-form-urlencoded',
        ];
        return contentType ? allowedTypes.includes(contentType) : false;
    }
    static isValidUserAgent(userAgent) {
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
exports.WebSecurity = WebSecurity;
/**
 * ZKPassport-specific utilities
 */
class ZKPassportUtils {
    static createVerificationRequest(_domain, purpose) {
        return {
            name: "Discord Admin Verification",
            logo: "https://zkpassport.id/favicon.png",
            purpose,
            scope: "adult",
            mode: "compressed-evm",
            devMode: process.env.NODE_ENV !== "production",
        };
    }
    static validateVerificationResponse(response) {
        return (response &&
            typeof response === 'object' &&
            typeof response.verified === 'boolean' &&
            (response.uniqueIdentifier === undefined || typeof response.uniqueIdentifier === 'string'));
    }
    static formatUniqueIdentifier(identifier) {
        if (identifier.length <= 16)
            return identifier;
        return `${identifier.substring(0, 8)}...${identifier.substring(identifier.length - 8)}`;
    }
}
exports.ZKPassportUtils = ZKPassportUtils;
//# sourceMappingURL=index.js.map