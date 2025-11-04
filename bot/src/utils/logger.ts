import { config } from '../config';
import { auditLogger } from '../../../shared/src/services/auditLogger';
import { logSanitizer, SanitizationPresets } from '../../../shared/src/security/logSanitizer';

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogEntry {
  level: LogLevel;
  message: string;
  timestamp: string;
  error?: Error;
  data?: any;
  sanitized?: boolean;
}

class Logger {
  private securityLoggingDepth: number = 0;
  private readonly maxSecurityDepth: number = 3;

  private getSanitizationOptions(): any {
    const environment = config.env as 'development' | 'test' | 'production';

    switch (environment) {
      case 'production':
        return SanitizationPresets.production;
      case 'test':
        return SanitizationPresets.test;
      default:
        return SanitizationPresets.development;
    }
  }

  private formatLog(level: LogLevel, message: string, error?: Error, data?: any): string {
    // Always output JSON format to enforce structured logging
    // Development environment: show full error details without sanitization
    if (config.env === 'development' && error) {
      const logEntry: LogEntry = {
        level,
        message,
        timestamp: new Date().toISOString(),
        sanitized: false,
        error: error,
        data: data
      };

      return JSON.stringify(logEntry);
    }

    // Production/other environments: sanitized error logging
    const sanitizationOptions = this.getSanitizationOptions();
    const sanitizedData = data ? logSanitizer.sanitize(data, sanitizationOptions) : undefined;
    const sanitizedError = error ? logSanitizer.sanitizeError(error, sanitizationOptions) : undefined;

    const logEntry: LogEntry = {
      level,
      message,
      timestamp: new Date().toISOString(),
      sanitized: true,
      ...(sanitizedError && { error: sanitizedError }),
      ...(sanitizedData && { data: sanitizedData })
    };

    return JSON.stringify(logEntry);
  }

  private log(level: LogLevel, message: string, data?: any, error?: Error, skipSecurityLogging: boolean = false): void {
    if (this.shouldLog(level)) {
      const formattedLog = this.formatLog(level, message, error, data);
      
      switch (level) {
        case 'error':
          console.error(formattedLog);
          break;
        case 'warn':
          console.warn(formattedLog);
          break;
        case 'info':
          console.info(formattedLog);
          break;
        case 'debug':
          console.log(formattedLog);
          break;
      }

      // Log security-sensitive events with recursion protection
      if (!skipSecurityLogging && this.securityLoggingDepth < this.maxSecurityDepth && this.isSecurityEvent(level, message, data)) {
        this.logSecurityEvent(message, data);
      }
    }
  }

  private isSecurityEvent(level: LogLevel, message: string, data?: any): boolean {
    const securityKeywords = ['security', 'violation', 'unauthorized', 'authentication', 'admin', 'permission', 'access', 'forbidden'];
    const messageText = (message + ' ' + JSON.stringify(data || {})).toLowerCase();
    return securityKeywords.some(keyword => messageText.includes(keyword)) || level === 'error';
  }

  private logSecurityEvent(message: string, data?: any): void {
    this.securityLoggingDepth++;
    
    try {
      const sanitizationOptions = this.getSanitizationOptions();
      const sanitizedData = logSanitizer.sanitize(data || {}, sanitizationOptions);
      
      auditLogger.logSecurityViolation('bot', 'log_security_event', {
        message: message.substring(0, 200),
        ...sanitizedData,
        source: 'bot_logger',
        depth: this.securityLoggingDepth
      });
    } catch (error) {
      console.error(`Failed to log security event: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      this.securityLoggingDepth--;
    }
  }

  debug(message: string, data?: any): void {
    this.log('debug', message, data);
  }

  info(message: string, data?: any): void {
    this.log('info', message, data);
  }

  warn(message: string, data?: any): void {
    this.log('warn', message, data);
  }

  error(message: string, error?: Error, data?: any): void {
    this.log('error', message, data, error);
  }

  // Audit logging methods with security sanitization
  logVerificationAttempt(userId: string, sessionId: string, verificationType: string, details?: any): void {
    const sanitizationOptions = this.getSanitizationOptions();
    const sanitizedDetails = logSanitizer.sanitize(details || {}, sanitizationOptions);
    
    auditLogger.logVerificationAttempt(userId, sessionId, verificationType, sanitizedDetails);
    this.info(`Verification attempt: ${verificationType}`, { userId, sessionId, verificationType, details: sanitizedDetails });
  }

  logVerificationResult(userId: string, sessionId: string, verificationType: string, success: boolean, details?: any, error?: string): void {
    const sanitizationOptions = this.getSanitizationOptions();
    const sanitizedDetails = logSanitizer.sanitize(details || {}, sanitizationOptions);
    const sanitizedError = error ? logSanitizer.sanitizeString(error, sanitizationOptions) : undefined;
    
    auditLogger.logVerificationResult(userId, sessionId, verificationType, success, sanitizedDetails, sanitizedError);
    
    if (success) {
      this.info(`Verification success: ${verificationType}`, { userId, sessionId, verificationType, details: sanitizedDetails });
    } else {
      this.warn(`Verification failure: ${verificationType}`, { userId, sessionId, verificationType, error: sanitizedError, details: sanitizedDetails });
    }
  }

  logSecurityViolation(userId: string, violationType: string, details?: any): void {
    const sanitizationOptions = this.getSanitizationOptions();
    const sanitizedDetails = logSanitizer.sanitize(details || {}, sanitizationOptions);
    
    auditLogger.logSecurityViolation(userId, violationType, sanitizedDetails);
    this.error(`Security violation: ${violationType}`, undefined, { userId, violationType, details: sanitizedDetails });
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
}

export const logger = new Logger();