import * as fs from 'fs';
import * as path from 'path';
import { pathValidator } from '../utils/pathSecurityValidator';
import { logger } from '../utils/logger';

// Temporarily disable absolute path blocking for audit logger initialization
pathValidator.addAllowedBase(path.join(process.cwd(), 'logs'));
pathValidator.addAllowedBase(path.join(process.cwd(), 'data'));
pathValidator.addAllowedBase(path.join(process.cwd(), 'temp'));
pathValidator.addAllowedBase(path.join(process.cwd(), 'uploads'));

export type AuditEventType =
    | 'verification_attempt'
    | 'verification_success'
    | 'verification_failure'
    | 'session_start'
    | 'session_end'
    | 'role_change'
    | 'role_assignment'
    | 'role_removal'
    | 'security_violation'
    | 'admin_action'
    | 'proof_replay_attempt'
    | 'invalid_proof_data'
    | 'duplicate_unique_id'
    | 'duplicate_discord_account'
    | 'invalid_session_token'
    | 'rate_limit_exceeded'
    | 'tampering_attempt'
    | 'user_communication'
    | 'error_recovery_attempt'
    | 'error_recovery_success'
    | 'error_recovery_failure'
    | 'timeout_event'
    | 'retry_attempt'
    | 'dm_send_success'
    | 'dm_send_failure'
    | 'progress_update';

export interface AuditEvent {
  timestamp: string;
  event: AuditEventType;
  userId?: string;
  sessionId?: string;
  verificationType?: string;
  ipAddress?: string;
  userAgent?: string;
  success?: boolean;
  details?: Record<string, any>;
  error?: string;
  actor?: string; // Who performed the action (for admin actions)
}

export interface AuditLogConfig {
  basePath: string;
  retentionDays: number;
  maxFileSize: number; // in bytes
  rotateInterval: 'daily' | 'hourly';
}

class AuditLogger {
  private config: AuditLogConfig;
  private currentLogFile: string = '';
  private logStream: fs.WriteStream | null = null;

  constructor(config?: Partial<AuditLogConfig>) {
    this.config = {
      basePath: config?.basePath || path.join(process.cwd(), 'logs', 'audit'),
      retentionDays: config?.retentionDays || 90,
      maxFileSize: config?.maxFileSize || 10 * 1024 * 1024, // 10MB
      rotateInterval: config?.rotateInterval || 'daily',
      ...config,
    };

    this.ensureLogDirectory();
    this.rotateLogFile();
    this.startLogRotation();
  }

  private ensureLogDirectory(): void {
    // Skip validation for audit logger base path since it's allowed by configuration
    const dir = this.config.basePath;
    if (!fs.existsSync(dir)) {
      try {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        logger.error('Failed to create audit log directory:', err);
        throw new Error(`Failed to create audit log directory: ${err.message}`);
      }
    }
  }

  private getLogFileName(): string {
    const now = new Date();
    const date = now.toISOString().split('T')[0]; // YYYY-MM-DD

    if (this.config.rotateInterval === 'hourly') {
      const hour = now.getUTCHours().toString().padStart(2, '0');
      return `audit-${date}-${hour}.jsonl`;
    }

    return `audit-${date}.jsonl`;
  }

  private rotateLogFile(): void {
    const newFile = this.getLogFileName();
    if (this.currentLogFile !== newFile) {
      if (this.logStream) {
        this.logStream.end();
      }

      this.currentLogFile = newFile;
      
      // Secure file path validation
      const validationResult = pathValidator.validatePath(newFile, this.config.basePath);
      if (!validationResult.isValid) {
        throw new Error(`Invalid log filename: ${validationResult.error}`);
      }

      // If validationResult.sanitizedPath is absolute, use it directly; otherwise join with base
      const filePath = path.isAbsolute(validationResult.sanitizedPath!) 
        ? validationResult.sanitizedPath!
        : path.join(this.config.basePath, validationResult.sanitizedPath!);
      try {
        this.logStream = fs.createWriteStream(filePath, { flags: 'a', mode: 0o600 });
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        logger.error('Failed to create audit log stream:', err);
        throw new Error(`Failed to create audit log stream: ${err.message}`);
      }
    }

    this.cleanupOldLogs();
  }

  private cleanupOldLogs(): void {
    try {
      const files = fs.readdirSync(this.config.basePath);
      const now = new Date();

      files.forEach(file => {
        // Validate filename for security
        const validationResult = pathValidator.validatePath(file, this.config.basePath);
        if (!validationResult.isValid) {
          logger.warn(`Skipping file during cleanup due to validation failure: ${file}`);
          return;
        }

        const validatedFile = validationResult.sanitizedPath!;
        if (!validatedFile.startsWith('audit-') || !validatedFile.endsWith('.jsonl')) return;

        const fileDate = this.extractDateFromFile(validatedFile);
        if (!fileDate) return;

        const ageInDays = (now.getTime() - fileDate.getTime()) / (1000 * 60 * 60 * 24);
        if (ageInDays > this.config.retentionDays) {
          const filePath = path.join(this.config.basePath, validatedFile);
          try {
            fs.unlinkSync(filePath);
            logger.debug(`Cleaned up old audit log: ${validatedFile}`);
          } catch (error) {
            const err = error instanceof Error ? error : new Error(String(error));
            logger.error(`Failed to delete old audit log ${validatedFile}:`, err);
          }
        }
      });
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error('Error during audit log cleanup:', err);
    }
  }

  private extractDateFromFile(filename: string): Date | null {
    const match = filename.match(/audit-(\d{4}-\d{2}-\d{2})/);
    if (match) {
      return new Date(match[1]);
    }
    return null;
  }

  private startLogRotation(): void {
    const interval = this.config.rotateInterval === 'hourly' ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000;
    setInterval(() => this.rotateLogFile(), interval);
  }

  log(event: AuditEvent): void {
    try {
      this.rotateLogFile(); // Check if rotation is needed

      const logEntry = JSON.stringify(event) + '\n';
      if (this.logStream) {
        this.logStream.write(logEntry);
      }
    } catch (error) {
      console.error('Failed to write audit log:', error);
    }
  }

  // Predefined logging methods for common events
  logVerificationAttempt(userId: string, sessionId: string, verificationType: string, details?: Record<string, any>): void {
    this.log({
      timestamp: new Date().toISOString(),
      event: 'verification_attempt',
      userId,
      sessionId,
      verificationType,
      details,
    });
  }

  logVerificationResult(userId: string, sessionId: string, verificationType: string, success: boolean, details?: Record<string, any>, error?: string): void {
    this.log({
      timestamp: new Date().toISOString(),
      event: success ? 'verification_success' : 'verification_failure',
      userId,
      sessionId,
      verificationType,
      success,
      details,
      error,
    });
  }

  logRoleChange(userId: string, actor: string, action: 'assignment' | 'removal', role: string, details?: Record<string, any>): void {
    this.log({
      timestamp: new Date().toISOString(),
      event: action === 'assignment' ? 'role_assignment' : 'role_removal',
      userId,
      actor,
      details: { role, ...details },
    });
  }

  logSessionEvent(userId: string, sessionId: string, action: 'start' | 'end', details?: Record<string, any>): void {
    this.log({
      timestamp: new Date().toISOString(),
      event: action === 'start' ? 'session_start' : 'session_end',
      userId,
      sessionId,
      details,
    });
  }

  logSecurityViolation(userId: string, violationType: string, details?: Record<string, any>): void {
    this.log({
      timestamp: new Date().toISOString(),
      event: 'security_violation',
      userId,
      details: { violationType, ...details },
    });
  }

  logSecurityEvent(eventType: string, details?: Record<string, any>, discordUserId?: string): void {
    // Sanitize details to remove potential PII beyond discordUserId
    const sanitizedDetails = details ? this.sanitizeDetails(details) : undefined;

    this.log({
      timestamp: new Date().toISOString(),
      event: eventType as AuditEventType,
      userId: discordUserId,
      details: sanitizedDetails,
    });
  }

  private sanitizeDetails(details: Record<string, any>): Record<string, any> {
    const sanitized = { ...details };

    // Remove common PII fields, only keep discordUserId if present
    delete sanitized.email;
    delete sanitized.name;
    delete sanitized.firstName;
    delete sanitized.lastName;
    delete sanitized.phone;
    delete sanitized.address;
    delete sanitized.ssn;
    delete sanitized.dob;
    delete sanitized.password;
    delete sanitized.token;
    delete sanitized.rawInput; // Remove any raw user input

    // Keep technical details like IP for security logging as per example
    // Only remove obviously sensitive string fields that look like user input

    return sanitized;
  }

  logAdminAction(actor: string, action: string, targetUserId?: string, details?: Record<string, any>): void {
    this.log({
      timestamp: new Date().toISOString(),
      event: 'admin_action',
      userId: targetUserId,
      actor,
      details: { action, ...details },
    });
  }

  // User communication logging methods
  logUserCommunication(userId: string, communicationType: 'dm_success' | 'dm_failure' | 'error_message' | 'progress_update' | 'recovery_suggestion', details?: Record<string, any>): void {
    this.log({
      timestamp: new Date().toISOString(),
      event: 'user_communication',
      userId,
      details: { communicationType, ...details },
    });
  }

  logErrorRecovery(userId: string, sessionId: string, recoveryType: 'retry' | 'timeout' | 'fallback', success: boolean, details?: Record<string, any>): void {
    this.log({
      timestamp: new Date().toISOString(),
      event: success ? 'error_recovery_success' : 'error_recovery_failure',
      userId,
      sessionId,
      success,
      details: { recoveryType, ...details },
    });
  }

  logTimeoutEvent(userId: string, sessionId: string, operation: string, timeoutMs: number, details?: Record<string, any>): void {
    this.log({
      timestamp: new Date().toISOString(),
      event: 'timeout_event',
      userId,
      sessionId,
      details: { operation, timeoutMs, ...details },
    });
  }

  logRetryAttempt(userId: string, sessionId: string, operation: string, attemptNumber: number, maxRetries: number, details?: Record<string, any>): void {
    this.log({
      timestamp: new Date().toISOString(),
      event: 'retry_attempt',
      userId,
      sessionId,
      details: { operation, attemptNumber, maxRetries, ...details },
    });
  }

  logProgressUpdate(userId: string, sessionId: string, step: string, details?: Record<string, any>): void {
    this.log({
      timestamp: new Date().toISOString(),
      event: 'progress_update',
      userId,
      sessionId,
      details: { step, ...details },
    });
  }

  // Query methods for retrieving logs (useful for database migration later)
  async getEvents(options: {
    userId?: string;
    event?: AuditEventType;
    since?: Date;
    until?: Date;
    limit?: number;
  } = {}): Promise<AuditEvent[]> {
    const { userId, event, since, until, limit = 100 } = options;
    
    try {
      // Get files with validation
      const allFiles = fs.readdirSync(this.config.basePath);
      const files = allFiles
        .filter(f => f.endsWith('.jsonl'))
        .filter(f => {
          const validationResult = pathValidator.validatePath(f, this.config.basePath);
          return validationResult.isValid;
        })
        .sort()
        .reverse();

      const events: AuditEvent[] = [];

      for (const file of files) {
        if (events.length >= limit) break;

        const filePath = path.join(this.config.basePath, file);
        let content: string;
        
        try {
          content = fs.readFileSync(filePath, 'utf-8');
        } catch (error) {
          const err = error instanceof Error ? error : new Error(String(error));
          logger.warn(`Failed to read audit log file ${file}:`, err);
          continue;
        }

        const lines = content.trim().split('\n');

        for (const line of lines) {
          if (events.length >= limit) break;

          try {
            const logEvent: AuditEvent = JSON.parse(line);

            // Apply filters
            if (userId && logEvent.userId !== userId) continue;
            if (event && logEvent.event !== event) continue;
            if (since && new Date(logEvent.timestamp) < since) continue;
            if (until && new Date(logEvent.timestamp) > until) continue;

            events.push(logEvent);
          } catch (error) {
            // Skip malformed lines but log the issue
            logger.debug('Skipping malformed audit log line:', { error: String(error), file });
            continue;
          }
        }
      }

      return events;
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error('Error reading audit events:', err);
      throw new Error(`Failed to read audit events: ${err.message}`);
    }
  }

  close(): void {
    if (this.logStream) {
      this.logStream.end();
      this.logStream = null;
    }
  }
}

// Export singleton instance
export const auditLogger = new AuditLogger();
export default auditLogger;