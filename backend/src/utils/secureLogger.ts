import { config } from '../config';
import { secureAuditLogger } from '@shared/security/secureAuditLogger';
import { logSanitizer, DataClassification, SanitizationPresets, type SanitizationOptions } from '@shared/security/logSanitizer';

interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
  meta?: any;
  securityContext?: any;
}

class Logger {
  private formatLog(level: string, message: string, meta?: any): string {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      message,
    };

    if (meta) {
      entry.meta = meta;
    }

    if (config.logging.format === 'json') {
      return JSON.stringify(entry);
    } else {
      const metaStr = meta ? ` | ${JSON.stringify(meta)}` : '';
      return `[${entry.timestamp}] ${entry.level}: ${message}${metaStr}`;
    }
  }

  private getClassificationForLevel(level: string): DataClassification {
    switch (level.toLowerCase()) {
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

  private getSanitizationOptions() {
    const environment = config.server.env as 'development' | 'test' | 'production';
    
    switch (environment) {
      case 'production':
        return SanitizationPresets.production;
      case 'test':
        return SanitizationPresets.test;
      default:
        return SanitizationPresets.development;
    }
  }

  private isSecurityRelevant(level: string, message: string, meta?: any): boolean {
    const securityKeywords = [
      'security', 'violation', 'unauthorized', 'forbidden', 'authentication',
      'authorization', 'session', 'token', 'credential', 'attack', 'breach',
      'hack', 'exploit', 'injection', 'csrf', 'xss'
    ];

    const messageLower = message.toLowerCase();
    const metaString = meta ? JSON.stringify(meta).toLowerCase() : '';

    return level === 'error' || 
           securityKeywords.some(keyword => 
             messageLower.includes(keyword) || metaString.includes(keyword)
           );
  }

  private sanitizeLogData(level: string, message: string, meta?: any) {
    // Get sanitization options based on environment
    const sanitizationOptions: SanitizationOptions = {
      classification: this.getClassificationForLevel(level),
      environment: config.server.env as any,
      allowStackTraces: config.server.env === 'development',
      maskSessionIds: config.server.env !== 'development',
      maskTokens: true,
      maskUserIds: config.server.env !== 'development'
    };

    // Sanitize metadata and message
    const sanitizedMeta = meta ? logSanitizer.sanitize(meta, sanitizationOptions) : undefined;
    const sanitizedMessage = logSanitizer.sanitizeString(message, sanitizationOptions);

    // Log to secure audit logger if it's a security-relevant event
    if (this.isSecurityRelevant(level, sanitizedMessage, sanitizedMeta)) {
      secureAuditLogger.logSecurityViolationEvent('unknown', 'application_log', {
        level,
        message: sanitizedMessage,
        metadata: sanitizedMeta
      });
    }

    return { sanitizedMessage, sanitizedMeta };
  }

  private log(level: string, message: string, meta?: any) {
    // Environment-based filtering: in production, only log info and above
    if (config.server.env === 'production' && level === 'debug') {
      return;
    }

    // Sanitize data before logging
    const { sanitizedMessage, sanitizedMeta } = this.sanitizeLogData(level, message, meta);
    const formattedLog = this.formatLog(level, sanitizedMessage, sanitizedMeta);

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
        console.debug(formattedLog);
        break;
      default:
        console.log(formattedLog);
    }
  }

  private shouldLog(level: string): boolean {
    // Environment-based filtering: in production, only log info and above
    if (config.server.env === 'production' && level === 'debug') {
      return false;
    }

    const levels = ['debug', 'info', 'warn', 'error'];
    const currentLevelIndex = levels.indexOf(config.logging.level);
    const messageLevelIndex = levels.indexOf(level);
    return messageLevelIndex >= currentLevelIndex;
  }

  debug(message: string, meta?: any) {
    if (this.shouldLog('debug')) {
      this.log('debug', message, meta);
    }
  }

  info(message: string, meta?: any) {
    if (this.shouldLog('info')) {
      this.log('info', message, meta);
    }
  }

  warn(message: string, meta?: any) {
    if (this.shouldLog('warn')) {
      this.log('warn', message, meta);
    }
  }

  error(message: string, meta?: any) {
    if (this.shouldLog('error')) {
      this.log('error', message, meta);
    }
  }

  // Utility method for logging errors with stack traces
  logError(error: Error | unknown, context?: string) {
    // Use environment-specific sanitization presets for consistency
    const sanitizationOptions = this.getSanitizationOptions();
    
    if (config.server.env === 'development') {
      // Development: full error details for debugging
      const meta = {
        error: error instanceof Error ? {
          name: error.name,
          message: error.message,
          stack: error.stack,
        } : error,
        context,
      };
      this.error('An error occurred (development debug)', meta);
    } else {
      // Production/Test: use proper error sanitization
      const sanitizedError = error instanceof Error ?
        logSanitizer.sanitizeError(error, sanitizationOptions) :
        new Error('[SANITIZED_ERROR]');
        
      const meta = {
        error: {
          name: sanitizedError.name,
          message: sanitizedError.message,
          stack: sanitizedError.stack,
        },
        context,
      };

      const sanitizedMeta = logSanitizer.sanitize(meta, sanitizationOptions);
      this.error('An error occurred', sanitizedMeta);
    }
  }

  // Utility method for logging API requests
  logRequest(method: string, url: string, statusCode?: number, duration?: number) {
    const sanitizationOptions: SanitizationOptions = {
      classification: DataClassification.INTERNAL,
      environment: config.server.env as any,
      allowStackTraces: false,
      maskSessionIds: config.server.env !== 'development',
      maskTokens: true,
      maskUserIds: config.server.env !== 'development'
    };

    const meta = {
      method,
      url: logSanitizer.sanitizeString(url, sanitizationOptions),
      statusCode,
      duration: duration ? `${duration}ms` : undefined,
    };

    const sanitizedMeta = logSanitizer.sanitize(meta, sanitizationOptions);
    this.info('API Request', sanitizedMeta);
  }

  // Utility method for logging database operations
  logDatabase(operation: string, table: string, duration?: number, meta?: any) {
    const sanitizationOptions: SanitizationOptions = {
      classification: DataClassification.INTERNAL,
      environment: config.server.env as any,
      allowStackTraces: false,
      maskSessionIds: config.server.env !== 'development',
      maskTokens: true,
      maskUserIds: config.server.env !== 'development'
    };

    const logMeta = {
      ...logSanitizer.sanitize(meta || {}, sanitizationOptions),
      operation,
      table,
      duration: duration ? `${duration}ms` : undefined,
    };

    this.debug('Database Operation', logMeta);
  }

  // Secure audit logging methods
  logSecurityEvent(event: string, userId?: string, details?: any) {
    // Sanitize sensitive data before audit logging
    const sanitizationOptions: SanitizationOptions = {
      classification: DataClassification.RESTRICTED,
      environment: config.server.env as any,
      allowStackTraces: false,
      maskSessionIds: true,
      maskTokens: true,
      maskUserIds: true
    };

    const sanitizedDetails = details ? logSanitizer.sanitize(details, sanitizationOptions) : undefined;
    
    secureAuditLogger.logSecurityViolationEvent(userId || 'unknown', event, sanitizedDetails);
    this.warn(`Security Event: ${event}`, { userId, details: sanitizedDetails });
  }

  logAdminAction(action: string, actor: string, targetUserId?: string, details?: any) {
    const sanitizationOptions: SanitizationOptions = {
      classification: DataClassification.CONFIDENTIAL,
      environment: config.server.env as any,
      allowStackTraces: false,
      maskSessionIds: true,
      maskTokens: true,
      maskUserIds: true
    };

    const sanitizedDetails = details ? logSanitizer.sanitize(details, sanitizationOptions) : undefined;
    
    secureAuditLogger.logAdminAction(actor, action, targetUserId, sanitizedDetails);
    this.info(`Admin Action: ${action}`, { actor, targetUserId, details: sanitizedDetails });
  }
}

export const logger = new Logger();