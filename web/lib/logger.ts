/**
 * Production-safe logger for web application
 * Supports log levels, environment-based filtering, and comprehensive log sanitization
 */

import { logSanitizer, SanitizationPresets } from '../../shared/src/security/logSanitizer';

type LogLevel = 'debug' | 'info' | 'warn' | 'error';
type LogMeta = Record<string, unknown> | string | number | boolean | null | undefined;

class Logger {
  private levels: LogLevel[] = ['debug', 'info', 'warn', 'error'];
  private securityLoggingDepth: number = 0;
  private readonly maxSecurityDepth: number = 3;

  private getSanitizationOptions() {
    const environment = process.env.NODE_ENV as 'development' | 'test' | 'production';
    
    switch (environment) {
      case 'production':
        return SanitizationPresets.production;
      case 'test':
        return SanitizationPresets.test;
      default:
        return SanitizationPresets.development;
    }
  }

  private getLevelIndex(level: LogLevel): number {
    return this.levels.indexOf(level);
  }

  private shouldLog(level: LogLevel): boolean {
    // SECURITY FIX: Server-side only environment filtering
    // This file runs on server-side only, safe to access process.env
    
    const envLogLevel = process.env.LOG_LEVEL || 'info';
    const validLevels: LogLevel[] = ['debug', 'info', 'warn', 'error'];
    const currentLevelIndex = validLevels.indexOf(envLogLevel as LogLevel);
    const messageLevelIndex = validLevels.indexOf(level);

    // If invalid LOG_LEVEL, default to 'info'
    if (currentLevelIndex === -1) {
      return messageLevelIndex >= validLevels.indexOf('info');
    }

    return messageLevelIndex >= currentLevelIndex;
  }

  private isSecurityEvent(level: LogLevel, message: string, meta?: LogMeta): boolean {
    const securityKeywords = ['security', 'violation', 'unauthorized', 'authentication', 'admin', 'permission', 'access', 'forbidden'];
    const messageText = (message + ' ' + JSON.stringify(meta || {})).toLowerCase();
    return securityKeywords.some(keyword => messageText.includes(keyword)) || level === 'error';
  }

  private log(level: LogLevel, message: string, meta?: LogMeta, skipSecurityLogging: boolean = false) {
    if (!this.shouldLog(level)) {
      return;
    }

    // Sanitize sensitive data in metadata
    const sanitizationOptions = this.getSanitizationOptions();
    const sanitizedMeta = meta ? logSanitizer.sanitize(meta, sanitizationOptions) : undefined;

    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] ${level.toUpperCase()}: ${message}`;

    if (sanitizedMeta !== undefined) {
      console.log(logMessage, sanitizedMeta);
    } else {
      console.log(logMessage);
    }

    // Log security-sensitive events with recursion protection
    if (!skipSecurityLogging && this.securityLoggingDepth < this.maxSecurityDepth && this.isSecurityEvent(level, message, meta)) {
      this.logSecurityEventInternal(message, meta);
    }
  }

  private logSecurityEventInternal(message: string, meta?: LogMeta): void {
    this.securityLoggingDepth++;
    
    try {
      const sanitizationOptions = this.getSanitizationOptions();
      const sanitizedMeta = logSanitizer.sanitize(meta || {}, sanitizationOptions);
      
      // In a real implementation, this would use the secure audit logger
      // For now, we'll use a simple security event log
      const securityLog = {
        timestamp: new Date().toISOString(),
        event: 'web_security_event',
        message: message.substring(0, 200),
        details: sanitizedMeta,
        source: 'web_logger',
        depth: this.securityLoggingDepth
      };
      
      console.warn('[SECURITY] ' + JSON.stringify(securityLog));
    } catch (error) {
      console.error(`Failed to log security event: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      this.securityLoggingDepth--;
    }
  }

  debug(message: string, meta?: LogMeta) {
    this.log('debug', message, meta);
  }

  info(message: string, meta?: LogMeta) {
    this.log('info', message, meta);
  }

  warn(message: string, meta?: LogMeta) {
    this.log('warn', message, meta);
  }

  error(message: string, meta?: LogMeta) {
    this.log('error', message, meta);
  }

  // Security-specific logging methods
  logSecurityEvent(message: string, userId?: string, details?: LogMeta): void {
    const sanitizationOptions = this.getSanitizationOptions();
    const sanitizedDetails = logSanitizer.sanitize(details || {}, sanitizationOptions);
    
    this.log('warn', `Security Event: ${message}`, { userId, details: sanitizedDetails }, true);
  }

  logAdminAction(action: string, actor: string, targetUserId?: string, details?: LogMeta): void {
    const sanitizationOptions = this.getSanitizationOptions();
    const sanitizedDetails = logSanitizer.sanitize(details || {}, sanitizationOptions);
    
    this.log('info', `Admin Action: ${action}`, { actor, targetUserId, details: sanitizedDetails }, true);
  }

  // Verification-specific logging with sanitization
  logVerificationAttempt(userId: string, sessionId: string, verificationType: string, details?: LogMeta): void {
    const sanitizationOptions = this.getSanitizationOptions();
    const sanitizedDetails = logSanitizer.sanitize(details || {}, sanitizationOptions);
    
    this.info(`Verification attempt: ${verificationType}`, { userId, sessionId, verificationType, details: sanitizedDetails });
  }

  logVerificationResult(userId: string, sessionId: string, verificationType: string, success: boolean, details?: LogMeta, error?: string): void {
    const sanitizationOptions = this.getSanitizationOptions();
    const sanitizedDetails = logSanitizer.sanitize(details || {}, sanitizationOptions);
    const sanitizedError = error ? logSanitizer.sanitizeString(error, sanitizationOptions) : undefined;
    
    if (success) {
      this.info(`Verification success: ${verificationType}`, { userId, sessionId, verificationType, details: sanitizedDetails });
    } else {
      this.warn(`Verification failure: ${verificationType}`, { userId, sessionId, verificationType, error: sanitizedError, details: sanitizedDetails });
    }
  }
}

export const logger = new Logger();