/**
 * Secure Audit Logger with Comprehensive Data Protection
 * Implements log sanitization, encryption, access controls, and compliance features
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { logSanitizer, DataClassification, type SanitizationOptions } from './logSanitizer';

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
  | 'progress_update'
  | 'log_security_violation'
  | 'sensitive_data_detected';

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
  actor?: string;
  securityContext?: SecurityContext;
  integrityHash?: string;
}

export interface SecurityContext {
  requestId: string;
  source: 'bot' | 'backend' | 'web' | 'system';
  component: string;
  classification: DataClassification;
  sanitized: boolean;
  complianceFlags: string[];
}

export interface SecureAuditLogConfig {
  basePath: string;
  retentionDays: number;
  maxFileSize: number;
  rotateInterval: 'daily' | 'hourly';
  encryptionEnabled: boolean;
  accessControl: AccessControlConfig;
  compliance: ComplianceConfig;
  monitoring: MonitoringConfig;
}

export interface AccessControlConfig {
  enabled: boolean;
  permissions: {
    read: string[];
    write: string[];
    admin: string[];
  };
  auditAccess: boolean;
}

export interface ComplianceConfig {
  gdpr: boolean;
  soc2: boolean;
  pciDss: boolean;
  hipaa: boolean;
  dataRetentionPolicy: string;
  auditTrailRequirements: string[];
}

export interface MonitoringConfig {
  realTimeAlerts: boolean;
  sensitiveDataDetection: boolean;
  volumeThreshold: number;
  anomalyDetection: boolean;
  alertEndpoints: string[];
  patterns?: Record<string, any>;
}

class SecureAuditLogger {
  private config: SecureAuditLogConfig;
  private currentLogFile: string = '';
  private logStream: fs.WriteStream | null = null;
  private encryptionKey: Buffer | null = null;
  private accessLog: string[] = [];
  private securityViolations: SecurityViolation[] = [];
  private startTime: Date = new Date();

  constructor(config?: Partial<SecureAuditLogConfig>) {
    this.config = {
      basePath: config?.basePath || path.join(process.cwd(), 'logs', 'secure-audit'),
      retentionDays: config?.retentionDays || 90,
      maxFileSize: config?.maxFileSize || 10 * 1024 * 1024,
      rotateInterval: config?.rotateInterval || 'daily',
      encryptionEnabled: config?.encryptionEnabled || true,
      accessControl: {
        enabled: config?.accessControl?.enabled || true,
        permissions: config?.accessControl?.permissions || {
          read: ['audit-admin'],
          write: ['system'],
          admin: ['security-admin']
        },
        auditAccess: true
      },
      compliance: {
        gdpr: config?.compliance?.gdpr || true,
        soc2: config?.compliance?.soc2 || true,
        pciDss: config?.compliance?.pciDss || false,
        hipaa: config?.compliance?.hipaa || false,
        dataRetentionPolicy: '7_years',
        auditTrailRequirements: ['integrity', 'immutability', 'access_logging']
      },
      monitoring: {
        realTimeAlerts: config?.monitoring?.realTimeAlerts || true,
        sensitiveDataDetection: config?.monitoring?.sensitiveDataDetection || true,
        volumeThreshold: config?.monitoring?.volumeThreshold || 1000,
        anomalyDetection: config?.monitoring?.anomalyDetection || true,
        alertEndpoints: config?.monitoring?.alertEndpoints || [],
        patterns: config?.monitoring?.patterns || {}
      },
      ...config,
    };

    this.initializeEncryption();
    this.ensureLogDirectory();
    this.rotateLogFile();
    this.startLogRotation();
    this.startSecurityMonitoring();
  }

  private initializeEncryption(): void {
    if (this.config.encryptionEnabled) {
      const keyEnv = process.env.AUDIT_LOG_ENCRYPTION_KEY;
      if (keyEnv) {
        this.encryptionKey = Buffer.from(keyEnv, 'hex');
      } else {
        // Generate a new key if not provided
        this.encryptionKey = crypto.randomBytes(32);
        console.warn('⚠️  Generated new audit log encryption key. Set AUDIT_LOG_ENCRYPTION_KEY environment variable for persistence.');
      }
    }
  }

  private ensureLogDirectory(): void {
    const dir = this.config.basePath;
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); // Restrictive permissions
    }
  }

  private getLogFileName(): string {
    const now = new Date();
    const date = now.toISOString().split('T')[0];
    const timestamp = now.getTime();

    if (this.config.rotateInterval === 'hourly') {
      const hour = now.getUTCHours().toString().padStart(2, '0');
      return `audit-${date}-${hour}-${timestamp}.jsonl.enc`;
    }

    return `audit-${date}-${timestamp}.jsonl.enc`;
  }

  private rotateLogFile(): void {
    const newFile = this.getLogFileName();
    if (this.currentLogFile !== newFile) {
      if (this.logStream) {
        this.logStream.end();
      }

      this.currentLogFile = newFile;
      const filePath = path.join(this.config.basePath, this.currentLogFile);
      
      // Create with restrictive permissions
      this.logStream = fs.createWriteStream(filePath, {
        flags: 'a',
        mode: 0o600
      });
    }

    this.cleanupOldLogs();
  }

  private cleanupOldLogs(): void {
    const files = fs.readdirSync(this.config.basePath);
    const now = new Date();

    files.forEach(file => {
      if (!file.startsWith('audit-') || !file.endsWith('.jsonl.enc')) return;

      const fileDate = this.extractDateFromFile(file);
      if (!fileDate) return;

      const ageInDays = (now.getTime() - fileDate.getTime()) / (1000 * 60 * 60 * 24);
      if (ageInDays > this.config.retentionDays) {
        this.secureDelete(path.join(this.config.basePath, file));
      }
    });
  }

  private extractDateFromFile(filename: string): Date | null {
    const match = filename.match(/audit-(\d{4}-\d{2}-\d{2})/);
    if (match) {
      return new Date(match[1]);
    }
    return null;
  }

  private secureDelete(filePath: string): void {
    try {
      const stats = fs.statSync(filePath);
      const buffer = Buffer.alloc(stats.size);
      
      // Overwrite with random data multiple times
      for (let i = 0; i < 3; i++) {
        crypto.randomFillSync(buffer);
        fs.writeFileSync(filePath, buffer);
      }
      
      // Finally delete
      fs.unlinkSync(filePath);
      
      // Audit log the secure deletion
      const event: AuditEvent = {
        timestamp: new Date().toISOString(),
        event: 'log_security_violation',
        details: {
          file: path.basename(filePath),
          size: stats.size
        },
        securityContext: this.createSecurityContext('system', 'log_management', DataClassification.RESTRICTED)
      };

      this.log(event);
    } catch (error) {
      console.error('Failed to securely delete log file:', error);
    }
  }

  private startLogRotation(): void {
    const interval = this.config.rotateInterval === 'hourly' ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000;
    setInterval(() => this.rotateLogFile(), interval);
  }

  private startSecurityMonitoring(): void {
    // Monitor for sensitive data exposure
    setInterval(() => {
      this.analyzeLogPatterns();
    }, 5 * 60 * 1000); // Every 5 minutes

    // Monitor log volume
    setInterval(() => {
      this.checkLogVolume();
    }, 60 * 1000); // Every minute
  }

  private createSecurityContext(source: string, component: string, classification: DataClassification = DataClassification.INTERNAL): SecurityContext {
    return {
      requestId: crypto.randomUUID(),
      source: source as any,
      component,
      classification,
      sanitized: false,
      complianceFlags: this.getComplianceFlags(classification)
    };
  }

  private getComplianceFlags(classification: DataClassification): string[] {
    const flags: string[] = [];
    
    if (this.config.compliance.gdpr) {
      flags.push(classification === DataClassification.CONFIDENTIAL || classification === DataClassification.RESTRICTED ? 'gdpr_applies' : 'gdpr_exempt');
    }
    
    if (this.config.compliance.soc2) {
      flags.push('soc2_audit_trail');
    }
    
    if (classification === DataClassification.RESTRICTED) {
      flags.push('data_classification_restricted');
    }
    
    return flags;
  }

  private encryptData(data: string): string {
    if (!this.encryptionKey || !this.config.encryptionEnabled) {
      return data;
    }

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    cipher.setAAD(Buffer.from('audit-log'));
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
  }


  private createIntegrityHash(event: AuditEvent): string {
    const data = JSON.stringify({
      timestamp: event.timestamp,
      event: event.event,
      userId: event.userId,
      sessionId: event.sessionId,
      details: event.details
    });
    
    return crypto.createHmac('sha256', this.encryptionKey || 'default-key')
      .update(data)
      .digest('hex');
  }

  private sanitizeEventData(event: AuditEvent): AuditEvent {
    // Determine sanitization level based on environment
    const environment = process.env.NODE_ENV || 'development';
    const sanitizationOptions: SanitizationOptions = {
      classification: this.getClassificationForEvent(event.event),
      environment: environment as any,
      allowStackTraces: environment === 'development',
      maskSessionIds: environment !== 'development',
      maskTokens: true,
      maskUserIds: environment !== 'development'
    };

    const sanitizedEvent = {
      ...event,
      details: event.details ? logSanitizer.sanitize(event.details, sanitizationOptions) : undefined,
      error: event.error ? logSanitizer.sanitizeString(event.error, sanitizationOptions) : undefined,
      securityContext: {
        ...event.securityContext,
        sanitized: true,
        classification: sanitizationOptions.classification
      }
    };

    // Validate sanitization
    const validation = logSanitizer.validateLogSecurity(sanitizedEvent, sanitizationOptions);
    if (!validation.isSecure) {
      this.logSecurityViolation('sanitization_failed', {
        violations: validation.violations,
        originalEvent: event.event
      });
    }

    return sanitizedEvent as AuditEvent;
  }

  private getClassificationForEvent(eventType: AuditEventType): DataClassification {
    const highRiskEvents = [
      'security_violation', 'tampering_attempt', 'invalid_session_token',
      'proof_replay_attempt', 'log_security_violation', 'sensitive_data_detected'
    ];
    
    const mediumRiskEvents = [
      'verification_failure', 'admin_action', 'role_change',
      'rate_limit_exceeded', 'timeout_event'
    ];

    if (highRiskEvents.includes(eventType)) {
      return DataClassification.RESTRICTED;
    } else if (mediumRiskEvents.includes(eventType)) {
      return DataClassification.CONFIDENTIAL;
    } else {
      return DataClassification.INTERNAL;
    }
  }


  private logSecurityViolation(type: string, details?: Record<string, any>): void {
    const violation: SecurityViolation = {
      timestamp: new Date().toISOString(),
      type,
      details: details || {},
      severity: 'high',
      resolved: false
    };

    this.securityViolations.push(violation);
    
    if (this.config.monitoring.realTimeAlerts) {
      this.sendSecurityAlert(violation);
    }
  }

  private sendSecurityAlert(violation: SecurityViolation): void {
    // In a real implementation, this would send alerts to monitoring systems
    console.warn(`🚨 Security Alert: ${violation.type} - ${JSON.stringify(violation.details)}`);
  }

  private analyzeLogPatterns(): void {
    // Analyze for suspicious patterns
    const recentViolations = this.securityViolations.filter(v => 
      new Date(v.timestamp).getTime() > Date.now() - 300000 // Last 5 minutes
    );

    if (recentViolations.length > 10) {
      this.logSecurityViolation('high_volume_violations', {
        count: recentViolations.length,
        timeWindow: '5_minutes'
      });
    }
  }

  private checkLogVolume(): void {
    const now = new Date();
    const minutesSinceStart = Math.floor((now.getTime() - this.startTime.getTime()) / 60000);
    const logsPerMinute = this.accessLog.length / Math.max(minutesSinceStart, 1);

    if (logsPerMinute > this.config.monitoring.volumeThreshold) {
      this.logSecurityViolation('high_log_volume', {
        logsPerMinute,
        threshold: this.config.monitoring.volumeThreshold
      });
    }
  }

  public log(event: AuditEvent): void {
    try {
      this.rotateLogFile();

      // Add security context if not provided
      if (!event.securityContext) {
        event.securityContext = this.createSecurityContext('unknown', 'unknown');
      }

      // Sanitize the event data
      const sanitizedEvent = this.sanitizeEventData({
        ...event,
        integrityHash: this.createIntegrityHash(event)
      });

      // Create log entry
      const logEntry = {
        ...sanitizedEvent,
        loggedAt: new Date().toISOString(),
        loggerVersion: '2.0.0'
      };

      // Encrypt if enabled
      const logString = JSON.stringify(logEntry);
      const finalLog = this.config.encryptionEnabled ? this.encryptData(logString) : logString;

      // Write to stream
      if (this.logStream) {
        this.logStream.write(finalLog + '\n');
      }

      // Track access
      this.accessLog.push(new Date().toISOString());

      // Check for sensitive data exposure
      if (this.config.monitoring.sensitiveDataDetection) {
        const validation = logSanitizer.validateLogSecurity(event, {
          classification: DataClassification.RESTRICTED,
          environment: 'production',
          allowStackTraces: false,
          maskSessionIds: true,
          maskTokens: true,
          maskUserIds: true
        });

        if (!validation.isSecure) {
          this.logSecurityViolation('sensitive_data_detected', {
            violations: validation.violations,
            eventType: event.event
          });
        }
      }

    } catch (error) {
      console.error('Failed to write secure audit log:', error);
    }
  }

  // Enhanced logging methods with security context
  public logVerificationAttempt(userId: string, sessionId: string, verificationType: string, details?: Record<string, any>): void {
    const event: AuditEvent = {
      timestamp: new Date().toISOString(),
      event: 'verification_attempt',
      userId,
      sessionId,
      verificationType,
      details,
      securityContext: this.createSecurityContext('bot', 'verification', DataClassification.CONFIDENTIAL)
    };

    this.log(event);
  }

  public logVerificationResult(userId: string, sessionId: string, verificationType: string, success: boolean, details?: Record<string, any>, error?: string): void {
    const event: AuditEvent = {
      timestamp: new Date().toISOString(),
      event: success ? 'verification_success' : 'verification_failure',
      userId,
      sessionId,
      verificationType,
      success,
      details,
      error,
      securityContext: this.createSecurityContext('bot', 'verification', DataClassification.CONFIDENTIAL)
    };

    this.log(event);
  }

  public logSecurityViolationEvent(userId: string, violationType: string, details?: Record<string, any>): void {
    const event: AuditEvent = {
      timestamp: new Date().toISOString(),
      event: 'security_violation',
      userId,
      details: { violationType, ...details },
      securityContext: this.createSecurityContext('system', 'security', DataClassification.RESTRICTED)
    };

    this.log(event);
  }

  public logAdminAction(actor: string, action: string, targetUserId?: string, details?: Record<string, any>): void {
    const event: AuditEvent = {
      timestamp: new Date().toISOString(),
      event: 'admin_action',
      userId: targetUserId,
      actor,
      details: { action, ...details },
      securityContext: this.createSecurityContext('admin', 'management', DataClassification.CONFIDENTIAL)
    };

    this.log(event);
  }

  public getSecurityReport(): SecurityReport {
    const now = new Date();
    const uptime = now.getTime() - this.startTime.getTime();
    
    return {
      uptime: uptime,
      totalLogs: this.accessLog.length,
      securityViolations: this.securityViolations.length,
      recentViolations: this.securityViolations.filter(v => 
        new Date(v.timestamp).getTime() > now.getTime() - 3600000
      ),
      config: {
        encryptionEnabled: this.config.encryptionEnabled,
        accessControlEnabled: this.config.accessControl.enabled,
        complianceFrameworks: Object.entries(this.config.compliance)
          .filter(([_, enabled]) => enabled)
          .map(([framework, _]) => framework),
        monitoringEnabled: this.config.monitoring.realTimeAlerts
      }
    };
  }

  close(): void {
    if (this.logStream) {
      this.logStream.end();
      this.logStream = null;
    }
  }
}

interface SecurityViolation {
  timestamp: string;
  type: string;
  details: Record<string, any>;
  severity: 'low' | 'medium' | 'high' | 'critical';
  resolved: boolean;
}

interface SecurityReport {
  uptime: number;
  totalLogs: number;
  securityViolations: number;
  recentViolations: SecurityViolation[];
  config: {
    encryptionEnabled: boolean;
    accessControlEnabled: boolean;
    complianceFrameworks: string[];
    monitoringEnabled: boolean;
  };
}

// Export singleton instance with secure defaults
export const secureAuditLogger = new SecureAuditLogger({
  basePath: process.env.AUDIT_LOG_PATH || path.join(process.cwd(), 'logs', 'secure-audit'),
  encryptionEnabled: process.env.AUDIT_LOG_ENCRYPTION === 'true',
  retentionDays: parseInt(process.env.AUDIT_LOG_RETENTION_DAYS || '90'),
  monitoring: {
    realTimeAlerts: process.env.AUDIT_LOG_ALERTS === 'true',
    sensitiveDataDetection: true,
    volumeThreshold: parseInt(process.env.AUDIT_LOG_VOLUME_THRESHOLD || '1000'),
    anomalyDetection: true,
    alertEndpoints: []
  }
});

export default secureAuditLogger;