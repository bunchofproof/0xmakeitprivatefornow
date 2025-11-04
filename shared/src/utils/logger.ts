import { logSanitizer, SanitizationPresets } from '../security/logSanitizer';

// interface LogEntry {
//   timestamp: string;
//   level: string;
//   message: string;
//   meta?: any;
//   sanitized?: boolean;
// }

class Logger {
  private securityLoggingDepth: number = 0;
  private readonly maxSecurityDepth: number = 3;

  private getSanitizationOptions(): any {
    // Default to development for shared utilities unless NODE_ENV is set
    const environment = (process.env.NODE_ENV as 'development' | 'test' | 'production') || 'development';
    
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

    const logObject = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      message,
      sanitized: true,
      ...sanitizedMeta,
    };

    return JSON.stringify(logObject);
  }

  private log(level: string, message: string, meta?: any, skipSecurityLogging: boolean = false) {
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

    // Log security-sensitive events with recursion protection
    if (!skipSecurityLogging && this.securityLoggingDepth < this.maxSecurityDepth && this.isSecurityEvent(level, message, meta)) {
      this.logSecurityEventInternal(message, meta);
    }
  }

  private isSecurityEvent(level: string, message: string, meta?: any): boolean {
    const securityKeywords = ['security', 'violation', 'unauthorized', 'authentication', 'admin', 'permission', 'access', 'forbidden'];
    const messageText = (message + ' ' + JSON.stringify(meta || {})).toLowerCase();
    return securityKeywords.some(keyword => messageText.includes(keyword)) || level === 'error';
  }

  private logSecurityEventInternal(message: string, meta?: any): void {
    this.securityLoggingDepth++;
    
    try {
      const sanitizationOptions = this.getSanitizationOptions();
      const sanitizedMeta = logSanitizer.sanitize(meta || {}, sanitizationOptions);
      
      // Log security event without sensitive data
      const securityLog = {
        timestamp: new Date().toISOString(),
        event: 'shared_security_event',
        message: message.substring(0, 200),
        details: sanitizedMeta,
        source: 'shared_logger',
        depth: this.securityLoggingDepth
      };
      
      console.warn('[SECURITY] ' + JSON.stringify(securityLog));
    } catch (error) {
      console.error(`Failed to log security event: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      this.securityLoggingDepth--;
    }
  }

  debug(message: string, meta?: any) {
    this.log('debug', message, meta);
  }

  info(message: string, meta?: any) {
    this.log('info', message, meta);
  }

  warn(message: string, meta?: any) {
    this.log('warn', message, meta);
  }

  error(message: string, meta?: any) {
    this.log('error', message, meta);
  }

  // Utility method for logging errors with stack traces and sanitization
  logError(error: Error | unknown, context?: string) {
    const sanitizationOptions = this.getSanitizationOptions();
    const sanitizedError = error instanceof Error ? logSanitizer.sanitizeError(error, sanitizationOptions) : error;
    
    const meta = {
      error: sanitizedError instanceof Error ? {
        name: sanitizedError.name,
        message: sanitizedError.message,
        stack: sanitizedError.stack ? '[SANITIZED_STACK_TRACE]' : undefined,
      } : sanitizedError,
      context,
    };

    this.error('An error occurred', meta);
  }

  // Security-specific logging methods
  logSecurityEvent(message: string, userId?: string, details?: any): void {
    const sanitizationOptions = this.getSanitizationOptions();
    const sanitizedDetails = logSanitizer.sanitize(details || {}, sanitizationOptions);
    
    this.log('warn', `Security Event: ${message}`, { userId, details: sanitizedDetails }, true);
  }

  logAdminAction(action: string, actor: string, targetUserId?: string, details?: any): void {
    const sanitizationOptions = this.getSanitizationOptions();
    const sanitizedDetails = logSanitizer.sanitize(details || {}, sanitizationOptions);
    
    this.log('info', `Admin Action: ${action}`, { actor, targetUserId, details: sanitizedDetails }, true);
  }
}

export const logger = new Logger();