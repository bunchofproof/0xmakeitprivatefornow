import { config } from '../config';
import { auditLogger } from '@shared/services/auditLogger';
import { logSanitizer, SanitizationPresets, DataClassification } from '@shared/security/logSanitizer';
import * as crypto from 'crypto';

interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
  meta?: any;
  sanitized?: boolean;
}

class Logger {
  private securityLoggingDepth: number = 0;
  private readonly maxSecurityDepth: number = 3;

  private getSanitizationOptions(): any {
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

  private formatLog(level: string, message: string, meta?: any): string {
    // Sanitize sensitive data in metadata
    const sanitizationOptions = this.getSanitizationOptions();
    const sanitizedMeta = meta ? logSanitizer.sanitize(meta, sanitizationOptions) : undefined;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      message,
      sanitized: true
    };

    if (sanitizedMeta) {
      entry.meta = sanitizedMeta;
    }

    if (config.logging.format === 'json') {
      return JSON.stringify(entry);
    } else {
      const metaStr = sanitizedMeta ? ` | ${JSON.stringify(sanitizedMeta)}` : '';
      return `[${entry.timestamp}] ${entry.level}: ${message}${metaStr}`;
    }
  }

  private log(level: string, message: string, meta?: any, skipSecurityLogging: boolean = false) {
    // Environment-based filtering: in production, only log info and above
    if (config.server.env === 'production' && level === 'debug') {
      return;
    }

    const formattedLog = this.formatLog(level, message, meta);

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

    // Log security-sensitive events to secure audit logger (with recursion protection)
    if (!skipSecurityLogging && this.securityLoggingDepth < this.maxSecurityDepth && this.isSecurityEvent(level, message, meta)) {
      this.logSecurityEvent(message, meta);
    }
  }

  private isSecurityEvent(level: string, message: string, meta?: any): boolean {
    const securityKeywords = ['security', 'violation', 'unauthorized', 'authentication', 'admin', 'permission', 'access', 'forbidden'];
    const messageText = (message + ' ' + JSON.stringify(meta || {})).toLowerCase();
    return securityKeywords.some(keyword => messageText.includes(keyword)) || level === 'error';
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
    const sanitizationOptions = this.getSanitizationOptions();
    
    if (config.server.env === 'development') {
      // Development environment: show full error details without sanitization
      const fullMeta = {
        fullError: error instanceof Error ? {
          name: error.name,
          message: error.message,
          stack: error.stack,
        } : error,
        context,
      };
      
      // Log full error details in development for debugging
      console.error('=== FULL ERROR DEBUG ===');
      console.error('Context:', context);
      console.error('Error Name:', error instanceof Error ? error.name : 'Unknown');
      console.error('Error Message:', error instanceof Error ? error.message : error);
      console.error('Error Stack:', error instanceof Error ? error.stack : 'No stack trace');
      console.error('========================');
      
      this.error('An error occurred (development debug)', fullMeta);
    } else {
      // Production/Test: sanitized error logging using logSanitizer
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
    const meta = {
      method,
      url,
      statusCode,
      duration: duration ? `${duration}ms` : undefined,
    };

    this.info('API Request', meta);
  }

  // Utility method for logging database operations
  logDatabase(operation: string, table: string, duration?: number, meta?: any) {
    const logMeta = {
      ...meta,
      operation,
      table,
      duration: duration ? `${duration}ms` : undefined,
    };

    this.debug('Database Operation', logMeta);
  }

  // Audit logging methods with security sanitization
  logSecurityEvent(event: string, userId?: string, details?: any) {
    const sanitizationOptions = this.getSanitizationOptions();
    const sanitizedDetails = logSanitizer.sanitize(details || {}, sanitizationOptions);
    
    auditLogger.logSecurityViolation(userId || 'system', event, {
      ...sanitizedDetails,
      source: 'backend'
    });
    this.log('warn', `Security Event: ${event}`, { userId, details: sanitizedDetails }, true);
  }

  logAdminAction(action: string, actor: string, targetUserId?: string, details?: any) {
    const sanitizationOptions = this.getSanitizationOptions();
    const sanitizedDetails = logSanitizer.sanitize(details || {}, sanitizationOptions);
    
    auditLogger.logAdminAction(actor, action, targetUserId, sanitizedDetails);
    this.log('info', `Admin Action: ${action}`, { actor, targetUserId, details: sanitizedDetails }, true);
  }
}

export const logger = new Logger();