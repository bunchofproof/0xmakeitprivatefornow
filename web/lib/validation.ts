/**
 * Client-side input validation and sanitization for the web interface
 * Implements comprehensive validation to prevent XSS and injection attacks
 */

export interface ValidationResult {
  isValid: boolean;
  value?: string;
  error?: string;
  errorType?: 'format' | 'length' | 'malicious' | 'required';
}

export class WebInputValidator {
  /**
   * Validate and sanitize verification token input
   */
  static validateToken(token: string): ValidationResult {
    if (!token || typeof token !== 'string') {
      return {
        isValid: false,
        error: 'Token is required',
        errorType: 'required'
      };
    }

    const trimmedToken = token.trim();

    // Check length constraints
    if (trimmedToken.length === 0) {
      return {
        isValid: false,
        error: 'Token cannot be empty',
        errorType: 'required'
      };
    }

    if (trimmedToken.length < 10) {
      return {
        isValid: false,
        error: 'Token is too short',
        errorType: 'length'
      };
    }

    if (trimmedToken.length > 200) {
      return {
        isValid: false,
        error: 'Token is too long',
        errorType: 'length'
      };
    }

    // Check for valid characters (alphanumeric, hyphens, underscores)
    if (!/^[a-zA-Z0-9_-]+$/.test(trimmedToken)) {
      return {
        isValid: false,
        error: 'Token contains invalid characters',
        errorType: 'format'
      };
    }

    // Check for potentially malicious patterns
    if (this.containsMaliciousPatterns(trimmedToken)) {
      return {
        isValid: false,
        error: 'Token contains invalid content',
        errorType: 'malicious'
      };
    }

    return {
      isValid: true,
      value: trimmedToken
    };
  }

  /**
   * Validate and sanitize search parameters
   */
  static validateSearchParams(params: URLSearchParams): ValidationResult {
    const token = params.get('token');
    const session = params.get('session');
    const type = params.get('type');

    if (!token || !session) {
      return {
        isValid: false,
        error: 'Missing required parameters',
        errorType: 'required'
      };
    }

    // Validate token
    const tokenValidation = this.validateToken(token);
    if (!tokenValidation.isValid) {
      return tokenValidation;
    }

    // Validate session
    const sessionValidation = this.validateSessionId(session);
    if (!sessionValidation.isValid) {
      return sessionValidation;
    }

    // Validate type if present
    if (type) {
      const typeValidation = this.validateVerificationType(type);
      if (!typeValidation.isValid) {
        return typeValidation;
      }
    }

    return {
      isValid: true,
      value: `token=${encodeURIComponent(tokenValidation.value!)}&session=${encodeURIComponent(sessionValidation.value!)}`
    };
  }

  /**
   * Validate session ID format
   */
  static validateSessionId(sessionId: string): ValidationResult {
    if (!sessionId || typeof sessionId !== 'string') {
      return {
        isValid: false,
        error: 'Session ID is required',
        errorType: 'required'
      };
    }

    const trimmedSession = sessionId.trim();

    if (trimmedSession.length === 0) {
      return {
        isValid: false,
        error: 'Session ID cannot be empty',
        errorType: 'required'
      };
    }

    if (trimmedSession.length > 100) {
      return {
        isValid: false,
        error: 'Session ID is too long',
        errorType: 'length'
      };
    }

    // Check for valid characters (alphanumeric, hyphens)
    if (!/^[a-zA-Z0-9_-]+$/.test(trimmedSession)) {
      return {
        isValid: false,
        error: 'Session ID contains invalid characters',
        errorType: 'format'
      };
    }

    // Check for potentially malicious patterns
    if (this.containsMaliciousPatterns(trimmedSession)) {
      return {
        isValid: false,
        error: 'Session ID contains invalid content',
        errorType: 'malicious'
      };
    }

    return {
      isValid: true,
      value: trimmedSession
    };
  }

  /**
   * Validate verification type
   */
  static validateVerificationType(type: string): ValidationResult {
    const validTypes = ['personhood', 'age', 'nationality', 'residency', 'kyc'];
    
    if (!type || typeof type !== 'string') {
      return {
        isValid: false,
        error: 'Verification type is required',
        errorType: 'required'
      };
    }

    const trimmedType = type.trim().toLowerCase();

    if (!validTypes.includes(trimmedType)) {
      return {
        isValid: false,
        error: `Invalid verification type. Must be one of: ${validTypes.join(', ')}`,
        errorType: 'format'
      };
    }

    return {
      isValid: true,
      value: trimmedType
    };
  }

  /**
   * Check for potentially malicious input patterns
   */
  static containsMaliciousPatterns(input: string): boolean {
    const maliciousPatterns = [
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
      /<img\b[^>]*onerror/gi,
      
      // SQL injection patterns
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)/gi,
      /((%27)|('))((%6F)|o|(%4F))((%72)|r|(%52))/gi,
      /((%27)|('))((%6D)|m|(%4D))((%77)|w|(%57))/gi,
      /(\b(OR|AND)\b\s+(%27)|(')\s*[=%])/gi,
      
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

    return maliciousPatterns.some(pattern => pattern.test(input));
  }

  /**
   * Remove control characters from input string
   */
  static removeControlCharacters(str: string): string {
    // Create a string without control characters
    let result = '';
    for (let i = 0; i < str.length; i++) {
      const charCode = str.charCodeAt(i);
      // Allow printable characters and common whitespace
      if (charCode >= 32 && charCode !== 127) {
        result += str[i];
      }
    }
    return result;
  }

  /**
   * Sanitize input for safe display
   */
  static sanitizeForDisplay(input: string): string {
    if (typeof input !== 'string') {
      return '';
    }

    return this.removeControlCharacters(input)
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

  /**
   * Validate URL parameters and redirect to error page if invalid
   */
  static validateAndRedirect(params: URLSearchParams, router: { replace: (url: string) => void }): { isValid: boolean; errorType?: string } {
    const validation = this.validateSearchParams(params);

    if (!validation.isValid) {
      const errorType = validation.errorType || 'invalid_parameters';
      
      // Determine redirect URL based on error type
      let redirectUrl = `/error?type=${errorType}`;
      
      if (validation.error) {
        redirectUrl += `&message=${encodeURIComponent(validation.error)}`;
      }

      router.replace(redirectUrl);
      return { isValid: false, errorType };
    }

    return { isValid: true };
  }

  /**
   * Rate limiting for client-side requests
   */
  static checkClientRateLimit(action: string, maxAttempts: number = 5): boolean {
    const key = `rate_limit_${action}`;
    const now = Date.now();
    const windowMs = 60 * 1000; // 1 minute
    const stored = localStorage.getItem(key);
    
    if (!stored) {
      localStorage.setItem(key, JSON.stringify({
        count: 1,
        resetTime: now + windowMs
      }));
      return true;
    }

    try {
      const data = JSON.parse(stored);
      
      if (now > data.resetTime) {
        // Reset window
        localStorage.setItem(key, JSON.stringify({
          count: 1,
          resetTime: now + windowMs
        }));
        return true;
      }

      if (data.count >= maxAttempts) {
        return false;
      }

      data.count++;
      localStorage.setItem(key, JSON.stringify(data));
      return true;
    } catch {
      // Invalid stored data, reset
      localStorage.setItem(key, JSON.stringify({
        count: 1,
        resetTime: now + windowMs
      }));
      return true;
    }
  }

  /**
   * Clean up expired rate limit entries
   */
  static cleanupRateLimit(): void {
    const now = Date.now();
    
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);

      if (key && key.startsWith('rate_limit_')) {
        try {
          const data = JSON.parse(localStorage.getItem(key) || '{}');

          if (data.resetTime && now > data.resetTime) {
            localStorage.removeItem(key);
          }
        } catch {
          // Invalid data, remove it
          localStorage.removeItem(key);
        }
      }
    }
  }
}

// Initialize rate limit cleanup
if (typeof window !== 'undefined') {
  // Clean up every 5 minutes
  setInterval(() => {
    WebInputValidator.cleanupRateLimit();
  }, 5 * 60 * 1000);
}

/**
 * Utility for parameter validation compatibility
 */
export const validateVerificationParameters = WebInputValidator.validateSearchParams;