import { config } from '../config';
import { secureAuditLogger } from '@shared/security/secureAuditLogger';
import { logSanitizer, DataClassification, type SanitizationOptions } from '@shared/security/logSanitizer';

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogEntry {
  level: LogLevel;
  message: string;
  timestamp: string;
  error?: Error;
  data?: any;
  securityContext?: any;
}

class Logger {
  private isJsonFormat(): boolean {
    return config.logging.format === 'json';
  }

  private getClassificationForLevel(level: LogLevel): DataClassification {
    switch (level) {
      case 'error':
        return DataClassification.CONFIDENTIAL;
      case 'warn':
        return DataClassification.INTERNAL;
      case 'debug':
        return DataClassification.PUBLIC;
      case 'info':
      default:
        return DataClassification.INTERNAL;
    }
  }

  private isSecurityRelevant(level: LogLevel, message: string, data?: any): boolean {
    const securityKeywords = [
      'security', 'violation', 'unauthorized', 'forbidden', 'authentication',
      'authorization', 'session', 'token', 'credential', 'attack', 'breach',
      'hack', 'exploit', 'injection', 'csrf', 'xss', 'verification'
    ];

    const messageLower = message.toLowerCase();
    const dataString = data ? JSON.stringify(data).toLowerCase() : '';

    return level === 'error' || 
           level === 'warn' ||
           securityKeywords.some(keyword => 
             messageLower.includes(keyword) || dataString.includes(keyword)
           );
  }

  private sanitizeLogData(level: LogLevel, message: string, data?: any) {
    // Get sanitization options based on environment
    const sanitizationOptions: SanitizationOptions = {
      classification: this.getClassificationForLevel(level),
      environment: config.env as any,
      allowStackTraces: config.env === 'development',
      maskSessionIds: config.env !== 'development',
      maskTokens: true,
      maskUserIds: config.env !== 'development'
    };

    // Sanitize data before logging
    const sanitizedData = data ? logSanitizer.sanitize(data, sanitizationOptions) : undefined;
    const sanitizedMessage = logSanitizer.sanitizeString(message, sanitizationOptions);

    // Log to secure audit logger if it's a security-relevant event
    if (this.isSecurityRelevant(level, sanitizedMessage, sanitizedData)) {
      secureAuditLogger.logSecurityViolationEvent('unknown', 'bot_application_log', {
        level,
        message: sanitizedMessage,
        data: sanitizedData
      });
    }

    return { sanitizedMessage, sanitizedData, sanitizationOptions };
  }

  private formatLog(level: LogLevel, message: string, error?: Error, data?: any): string {
    const sanitized = this.sanitizeLogData(level, message, data);
    
    const logEntry: LogEntry = {
      level,
      message: sanitized.sanitizedMessage,
      timestamp: new Date().toISOString(),
      ...(error && { error: error.message }),
      ...(sanitized.sanitizedData && { data: sanitized.sanitizedData })
    };

    if (this.isJsonFormat()) {
      return JSON.stringify(logEntry);
    }

    const timestamp = new Date().toLocaleTimeString();
    let formatted = `[${timestamp}] ${level.toUpperCase()}: ${sanitized.sanitizedMessage}`;

    if (error) {
      formatted += `\nError: ${error.message}`;
      if (error.stack && config.logging.level === 'debug') {
        formatted += `\nStack: ${error.stack}`;
      }
    }

    if (sanitized.sanitizedData && config.logging.level === 'debug') {
      formatted += `\nData: ${JSON.stringify(sanitized.sanitizedData, null, 2)}`;
    }

    return formatted;
  }

  debug(message: string, data?: any): void {
    if (this.shouldLog('debug')) {
      console.log(this.formatLog('debug', message, undefined, data));
    }
  }

  info(message: string, data?: any): void {
    if (this.shouldLog('info')) {
      console.log(this.formatLog('info', message, undefined, data));
    }
  }

  warn(message: string, data?: any): void {
    if (this.shouldLog('warn')) {
      console.warn(this.formatLog('warn', message, undefined, data));
    }
  }

  error(message: string, error?: Error, data?: any): void {
    if (this.shouldLog('error')) {
      console.error(this.formatLog('error', message, error, data));
    }
  }

  private shouldLog(level: LogLevel): boolean {
    // Environment-based filtering: in production, only log info and above
    if (config.env === 'production' && level === 'debug') {
      return false;
    }

    const levels = ['debug', 'info', 'warn', 'error'];
    const currentLevelIndex = levels.indexOf(config.logging.level);
    const messageLevelIndex = levels.indexOf(level);
    return messageLevelIndex >= currentLevelIndex;
  }

  // Secure audit logging methods with sanitization
  logVerificationAttempt(userId: string, sessionId: string, verificationType: string, details?: any): void {
    const sanitizationOptions: SanitizationOptions = {
      classification: DataClassification.CONFIDENTIAL,
      environment: config.env as any,
      allowStackTraces: false,
      maskSessionIds: config.env !== 'development',
      maskTokens: true,
      maskUserIds: config.env !== 'development'
    };

    const sanitizedDetails = details ? logSanitizer.sanitize(details, sanitizationOptions) : undefined;

    // Log to secure audit logger
    secureAuditLogger.logVerificationAttempt(
      this.maskUserId(userId), 
      this.maskSessionId(sessionId), 
      verificationType, 
      sanitizedDetails
    );

    // Also log to console with sanitized data
    this.info(`Verification attempt: ${verificationType}`, { 
      userId: this.maskUserId(userId), 
      sessionId: this.maskSessionId(sessionId), 
      verificationType, 
      details: sanitizedDetails 
    });
  }

  logVerificationResult(userId: string, sessionId: string, verificationType: string, success: boolean, details?: any, error?: string): void {
    const sanitizationOptions: SanitizationOptions = {
      classification: DataClassification.CONFIDENTIAL,
      environment: config.env as any,
      allowStackTraces: false,
      maskSessionIds: config.env !== 'development',
      maskTokens: true,
      maskUserIds: config.env !== 'development'
    };

    const sanitizedDetails = details ? logSanitizer.sanitize(details, sanitizationOptions) : undefined;
    const sanitizedError = error ? logSanitizer.sanitizeString(error, sanitizationOptions) : undefined;

    // Log to secure audit logger
    secureAuditLogger.logVerificationResult(
      this.maskUserId(userId),
      this.maskSessionId(sessionId),
      verificationType,
      success,
      sanitizedDetails,
      sanitizedError
    );

    // Also log to console with sanitized data
    if (success) {
      this.info(`Verification success: ${verificationType}`, { 
        userId: this.maskUserId(userId), 
        sessionId: this.maskSessionId(sessionId), 
        verificationType, 
        details: sanitizedDetails 
      });
    } else {
      this.warn(`Verification failure: ${verificationType}`, { 
        userId: this.maskUserId(userId), 
        sessionId: this.maskSessionId(sessionId), 
        verificationType, 
        error: sanitizedError, 
        details: sanitizedDetails 
      });
    }
  }

  logSecurityViolation(userId: string, violationType: string, details?: any): void {
    const sanitizationOptions: SanitizationOptions = {
      classification: DataClassification.RESTRICTED,
      environment: config.env as any,
      allowStackTraces: false,
      maskSessionIds: true,
      maskTokens: true,
      maskUserIds: true
    };

    const sanitizedDetails = details ? logSanitizer.sanitize(details, sanitizationOptions) : undefined;

    // Log to secure audit logger (critical security event)
    secureAuditLogger.logSecurityViolationEvent(
      this.maskUserId(userId),
      violationType,
      sanitizedDetails
    );

    // Log to console with high priority
    this.error(`Security violation: ${violationType}`, undefined, { 
      userId: this.maskUserId(userId), 
      violationType, 
      details: sanitizedDetails 
    });
  }

  // Helper methods for masking sensitive data
  private maskUserId(userId: string): string {
    if (config.env === 'development') {
      return userId;
    }
    // Mask Discord user ID: show only first 4 and last 4 characters
    return userId.length > 8 ? `${userId.substring(0, 4)}***${userId.substring(userId.length - 4)}` : '***';
  }

  private maskSessionId(sessionId: string): string {
    if (config.env === 'development') {
      return sessionId;
    }
    // Mask session ID: show only first 8 characters
    return sessionId.length > 8 ? `${sessionId.substring(0, 8)}***` : '***';
  }
}

export const logger = new Logger();