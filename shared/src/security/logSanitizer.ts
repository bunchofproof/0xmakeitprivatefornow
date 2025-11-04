/**
 * Comprehensive Log Sanitization System
 * Implements data classification and automatic sanitization for all log entries
 */

export enum DataClassification {
  PUBLIC = 'public',
  INTERNAL = 'internal',
  CONFIDENTIAL = 'confidential',
  RESTRICTED = 'restricted'
}

export interface SensitiveDataPattern {
  pattern: RegExp;
  classification: DataClassification;
  replacement: string;
  description: string;
}

export interface SanitizationOptions {
  classification: DataClassification;
  environment: 'development' | 'test' | 'production';
  allowStackTraces: boolean;
  maskSessionIds: boolean;
  maskTokens: boolean;
  maskUserIds: boolean;
}

export class LogSanitizer {
  private patterns: SensitiveDataPattern[];

  constructor() {
    this.patterns = this.initializePatterns();
  }

  private initializePatterns(): SensitiveDataPattern[] {
    return [
      // Session IDs (High Risk)
      {
        pattern: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
        classification: DataClassification.RESTRICTED,
        replacement: '[SESSION_ID_REDACTED]',
        description: 'Session identifiers'
      },
      // Discord User IDs (High Risk)
      {
        pattern: /\b\d{17,19}\b/g,
        classification: DataClassification.CONFIDENTIAL,
        replacement: '[USER_ID_REDACTED]',
        description: 'Discord user identifiers'
      },
      // JWT Tokens (Critical Risk)
      {
        pattern: /\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b/g,
        classification: DataClassification.RESTRICTED,
        replacement: '[JWT_TOKEN_REDACTED]',
        description: 'JWT authentication tokens'
      },
      // API Keys and Secrets (Critical Risk)
      {
        pattern: /\b[A-Za-z0-9]{32,}\b/g,
        classification: DataClassification.RESTRICTED,
        replacement: '[SECRET_REDACTED]',
        description: 'API keys and secrets'
      },
      // Password patterns (Critical Risk)
      {
        pattern: /["'](?:password|passwd|pwd|secret)["']:\s*["'][^"']{1,}["']/gi,
        classification: DataClassification.RESTRICTED,
        replacement: '[CREDENTIAL_REDACTED]',
        description: 'Passwords and credentials'
      },
      // Email addresses (High Risk)
      {
        pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
        classification: DataClassification.CONFIDENTIAL,
        replacement: '[EMAIL_REDACTED]',
        description: 'Email addresses'
      },
      // IP Addresses (Medium Risk)
      {
        pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
        classification: DataClassification.INTERNAL,
        replacement: '[IP_REDACTED]',
        description: 'IP addresses'
      },
      // IPv6 addresses (Medium Risk)
      {
        pattern: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
        classification: DataClassification.INTERNAL,
        replacement: '[IPV6_REDACTED]',
        description: 'IPv6 addresses'
      },
      // HMAC signatures (High Risk)
      {
        pattern: /\b[a-fA-F0-9]{64}\b/g,
        classification: DataClassification.RESTRICTED,
        replacement: '[HASH_REDACTED]',
        description: 'HMAC signatures and hashes'
      }
    ];
  }

  /**
   * Main sanitization method - sanitizes any log data
   */
  public sanitize(data: any, options: SanitizationOptions): any {
    if (typeof data === 'string') {
      return this.sanitizeString(data, options);
    }

    if (Array.isArray(data)) {
      return data.map(item => this.sanitize(item, options));
    }

    if (data && typeof data === 'object') {
      return this.sanitizeObject(data, options);
    }

    return data;
  }

  /**
   * Sanitizes a string value
   */
  public sanitizeString(value: string, options: SanitizationOptions): string {
    let sanitized = value;

    // Apply pattern-based sanitization
    for (const pattern of this.patterns) {
      if (this.shouldApplyPattern(pattern, options)) {
        sanitized = sanitized.replace(pattern.pattern, pattern.replacement);
      }
    }

    return sanitized;
  }

  /**
   * Sanitizes an object recursively
   */
  public sanitizeObject(obj: any, options: SanitizationOptions): any {
    const sanitized: any = {};

    for (const [key, value] of Object.entries(obj)) {
      const sanitizedKey = this.sanitizeKey(key, options);
      const sanitizedValue = this.sanitizeValue(value, options);
      
      // Only include non-null values
      if (sanitizedValue !== null && sanitizedValue !== undefined) {
        sanitized[sanitizedKey] = sanitizedValue;
      }
    }

    return sanitized;
  }

  /**
   * Sanitizes individual values
   */
  private sanitizeValue(value: any, options: SanitizationOptions): any {
    if (value === null || value === undefined) {
      return value;
    }

    // Handle sensitive field names
    if (typeof value === 'string') {
      return this.sanitizeString(value, options);
    }

    // Recursively sanitize objects and arrays
    if (typeof value === 'object') {
      return this.sanitize(value, options);
    }

    return value;
  }

  /**
   * Sanitizes object keys based on sensitivity
   */
  private sanitizeKey(key: string, options: SanitizationOptions): string {
    const sensitiveKeys = [
      'password', 'passwd', 'pwd', 'secret', 'token', 'auth', 'key', 'apiKey',
      'sessionId', 'sessionID', 'userId', 'userID', 'discordUserId', 'discordUserID',
      'email', 'phone', 'address', 'ssn', 'dob', 'ip', 'ipAddress', 'userAgent',
      'hmac', 'signature', 'hash', 'nonce', 'salt', 'verificationCode'
    ];

    const lowerKey = key.toLowerCase();
    
    for (const sensitiveKey of sensitiveKeys) {
      if (lowerKey.includes(sensitiveKey)) {
        if (options.environment === 'production') {
          return `[REDACTED_${sensitiveKey.toUpperCase()}]`;
        }
        return `***${key}`;
      }
    }

    return key;
  }

  /**
   * Determines if a pattern should be applied based on environment and classification
   */
  private shouldApplyPattern(pattern: SensitiveDataPattern, options: SanitizationOptions): boolean {
    const classificationHierarchy = {
      [DataClassification.PUBLIC]: 0,
      [DataClassification.INTERNAL]: 1,
      [DataClassification.CONFIDENTIAL]: 2,
      [DataClassification.RESTRICTED]: 3
    };

    const shouldApplyByClassification = classificationHierarchy[pattern.classification] >= classificationHierarchy[options.classification];

    const environmentFilters = {
      development: true, // Apply all sanitization in dev
      test: false,       // Apply only restricted in test
      production: false  // Apply only restricted in production
    };

    const shouldApplyByEnvironment = environmentFilters[options.environment];

    // Special handling for certain patterns
    if (options.maskSessionIds && pattern.pattern.toString().includes('session')) {
      return true;
    }

    if (options.maskTokens && (pattern.description.includes('token') || pattern.description.includes('secret'))) {
      return true;
    }

    if (options.maskUserIds && pattern.description.includes('user')) {
      return true;
    }

    return shouldApplyByClassification && shouldApplyByEnvironment;
  }

  /**
   * Sanitizes error objects specifically
   */
  public sanitizeError(error: Error, options: SanitizationOptions): Error {
    const sanitizedError = new Error('[SANITIZED_ERROR]');
    sanitizedError.stack = options.allowStackTraces ? error.stack : '[STACK_TRACE_REDACTED]';
    
    return sanitizedError;
  }

  /**
   * Creates sanitized log metadata
   */
  public createSecureMetadata(original: any, options: SanitizationOptions): any {
    const safeMetadata: any = {
      timestamp: new Date().toISOString(),
      sanitized: true,
      classification: options.classification
    };

    // Only include safe metadata fields
    if (typeof original === 'object' && original !== null) {
      for (const [key, value] of Object.entries(original)) {
        if (this.isSafeMetadataField(key)) {
          safeMetadata[key] = this.sanitizeValue(value, options);
        }
      }
    }

    return safeMetadata;
  }

  /**
   * Determines if a metadata field is safe to include in logs
   */
  private isSafeMetadataField(key: string): boolean {
    const safeFields = [
      'operation', 'service', 'component', 'function', 'method',
      'duration', 'status', 'code', 'type', 'category', 'level'
    ];

    return safeFields.includes(key.toLowerCase()) || 
           !this.isSensitiveKey(key.toLowerCase());
  }

  /**
   * Checks if a key contains sensitive information
   */
  private isSensitiveKey(key: string): boolean {
    const sensitivePatterns = [
      'id', 'user', 'session', 'token', 'auth', 'secret', 'key', 'password',
      'email', 'phone', 'address', 'ip', 'agent', 'credential', 'hash', 'hmac'
    ];

    return sensitivePatterns.some(pattern => key.includes(pattern));
  }

  /**
   * Validates that log data meets security requirements
   */
  public validateLogSecurity(data: any, options: SanitizationOptions): { isSecure: boolean; violations: string[] } {
    const violations: string[] = [];
    
    if (typeof data === 'string') {
      violations.push(...this.findViolations(data, options));
    } else if (typeof data === 'object' && data !== null) {
      const jsonString = JSON.stringify(data);
      violations.push(...this.findViolations(jsonString, options));
    }

    return {
      isSecure: violations.length === 0,
      violations
    };
  }

  /**
   * Finds security violations in log data
   */
  private findViolations(data: string, options: SanitizationOptions): string[] {
    const violations: string[] = [];

    for (const pattern of this.patterns) {
      if (this.shouldApplyPattern(pattern, options) && pattern.pattern.test(data)) {
        violations.push(`Potential ${pattern.classification} data exposure: ${pattern.description}`);
      }
    }

    return violations;
  }
}

// Export singleton instance
export const logSanitizer = new LogSanitizer();

// Sanitization presets for different environments
export const SanitizationPresets = {
  development: {
    classification: DataClassification.INTERNAL,
    environment: 'development' as const,
    allowStackTraces: true,
    maskSessionIds: false,
    maskTokens: true,
    maskUserIds: false
  },
  test: {
    classification: DataClassification.CONFIDENTIAL,
    environment: 'test' as const,
    allowStackTraces: false,
    maskSessionIds: true,
    maskTokens: true,
    maskUserIds: true
  },
  production: {
    classification: DataClassification.CONFIDENTIAL,
    environment: 'production' as const,
    allowStackTraces: false,
    maskSessionIds: true,
    maskTokens: true,
    maskUserIds: true
  }
};