// Session Security Manager - Atomic Session Management and Replay Prevention
// Provides robust session handling with atomic operations, replay detection,
// and comprehensive security monitoring to prevent session hijacking attacks.

import { randomBytes, createHash } from 'crypto';
import { databaseDriver } from './databaseDrivers';
import { DatabaseTransaction } from './databaseConcurrencyControl';
import { logger } from './logger';

// Session security configuration
export interface SessionSecurityConfig {
  maxSessionAge: number; // Maximum session age in milliseconds
  replayDetectionWindow: number; // Time window for replay detection
  maxReplayAttempts: number; // Maximum replay attempts before blocking
  sessionBindingEnabled: boolean; // Enable session binding to context
  encryptionEnabled: boolean; // Enable session data encryption
  auditLevel: 'basic' | 'detailed' | 'comprehensive'; // Audit logging level
}

// Default security configuration
export const defaultSessionSecurityConfig: SessionSecurityConfig = {
  maxSessionAge: 15 * 60 * 1000, // 15 minutes
  replayDetectionWindow: 60 * 1000, // 1 minute
  maxReplayAttempts: 3,
  sessionBindingEnabled: true,
  encryptionEnabled: true,
  auditLevel: 'comprehensive'
};

// Session binding information
export interface SessionBinding {
  ipAddress?: string;
  userAgent?: string;
  guildId?: string;
  verificationType?: string;
  deviceFingerprint?: string;
}

// Session usage context
export interface SessionUsageContext {
  sessionId: string;
  token: string;
  discordUserId: string;
  timestamp: Date;
  ipAddress?: string;
  userAgent?: string;
  guildId?: string;
  verificationType?: string;
  operation: 'create' | 'validate' | 'invalidate' | 'cleanup' | 'replay_detected';
  success: boolean;
  errorMessage?: string;
  bindingHash?: string; // Hash of session binding for validation
}

// Session replay attempt tracking
export interface SessionReplayAttempt {
  id: string;
  sessionId: string;
  token: string;
  discordUserId: string;
  attemptTimestamp: Date;
  contextHash: string;
  ipAddress?: string;
  userAgent?: string;
  detectionReason: 'token_reuse' | 'context_mismatch' | 'timing_anomaly' | 'geographic_anomaly';
  severity: 'low' | 'medium' | 'high' | 'critical';
  blocked: boolean;
}

// Session security events
export interface SessionSecurityEvent {
  id: string;
  sessionId: string;
  discordUserId: string;
  eventType: 'session_created' | 'session_used' | 'session_invalidated' | 'session_expired' | 'replay_attempt' | 'binding_violation' | 'security_alert';
  timestamp: Date;
  severity: 'info' | 'warning' | 'error' | 'critical' | 'high';
  description: string;
  metadata: Record<string, any>;
}

// Session performance metrics
export interface SessionPerformanceMetrics {
  sessionId: string;
  createdAt: Date;
  firstUsedAt?: Date;
  lastUsedAt?: Date;
  totalUsageCount: number;
  averageUsageInterval?: number;
  uniqueIpCount: number;
  uniqueUserAgentCount: number;
  replayAttemptsDetected: number;
  bindingViolations: number;
  finalStatus: 'completed' | 'expired' | 'invalidated' | 'compromised';
}

/**
 * Enhanced Session Security Manager with atomic operations
 */
export class SessionSecurityManager {
  private config: SessionSecurityConfig;

  constructor(config: Partial<SessionSecurityConfig> = {}) {
    this.config = { ...defaultSessionSecurityConfig, ...config };
  }

  /**
   * Create a new secure session with atomic operations
   */
  async createSecureSession(
    discordUserId: string,
    binding?: SessionBinding
  ): Promise<{
    sessionId: string;
    token: string;
    expiresAt: Date;
    bindingHash?: string;
  }> {
    const sessionId = randomBytes(32).toString('hex');
    const token = randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + this.config.maxSessionAge);

    // Generate binding hash if binding is provided
    let bindingHash: string | undefined;
    if (binding && this.config.sessionBindingEnabled) {
      bindingHash = this.generateBindingHash(binding);
    }

    const sessionData = {
      id: sessionId,
      token,
      discordUserId,
      expiresAt,
      used: false,
      createdAt: new Date(),
      bindingHash,
      usageCount: 0,
      lastUsedAt: null,
      invalidationAttempts: 0
    };

    try {
      // Create session with atomic transaction
      await databaseDriver.executeTransaction(['verification-sessions.json'], async (tx: any) => {
        const sessions = await tx.read('verification-sessions.json');
        
        // Check for existing active sessions for this user
        const existingSession = sessions.find((s: any) => 
          s.discordUserId === discordUserId && 
          s.expiresAt > new Date() && 
          !s.used
        );

        if (existingSession) {
          // Invalidate existing session atomically
          existingSession.used = true;
          existingSession.invalidationAttempts++;
          existingSession.lastUsedAt = new Date();
        }

        sessions.push(sessionData);
        await tx.write('verification-sessions.json', sessions);

        // Log security event
        await this.logSecurityEvent(tx, {
          sessionId,
          discordUserId,
          eventType: 'session_created',
          severity: 'info',
          description: `Secure session created for user ${discordUserId}`,
          metadata: {
            expiresAt: expiresAt.toISOString(),
            bindingHash,
            hasBinding: !!binding
          }
        });
      });

      logger.info(`Secure session created for user ${discordUserId}`, {
        sessionId,
        expiresAt: expiresAt.toISOString(),
        hasBinding: !!bindingHash
      });

      return {
        sessionId,
        token,
        expiresAt,
        bindingHash
      };

    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error('Failed to create secure session:', err);
      throw new Error('Failed to create secure session');
    }
  }

  /**
   * Atomically validate and invalidate a session for verification
   */
  async validateAndInvalidateSession(
    sessionId: string,
    context: SessionBinding
  ): Promise<{
    valid: boolean;
    sessionId?: string;
    discordUserId?: string;
    error?: string;
  }> {
    const contextHash = this.generateBindingHash(context);

    try {
      let result: { valid: boolean; sessionId?: string; discordUserId?: string; error?: string } = { valid: false, error: undefined };

      await databaseDriver.executeTransaction(['verification-sessions.json'], async (tx: any) => {
        const sessions = await tx.read('verification-sessions.json');
        
        // Find session by sessionId
        const session = sessions.find((s: any) => s.id === sessionId);
        
        if (!session) {
          result.error = 'Invalid session ID';
          await this.logSecurityEvent(tx, {
            sessionId: 'unknown',
            discordUserId: 'unknown',
            eventType: 'replay_attempt',
            severity: 'warning',
            description: `Invalid session ID used: ${sessionId.substring(0, 8)}...`,
            metadata: { sessionId: sessionId.substring(0, 8), contextHash }
          });
          return;
        }

        // Check if session is expired
        if (new Date() > new Date(session.expiresAt)) {
          result.error = 'Session expired';
          await this.logSecurityEvent(tx, {
            sessionId: session.id,
            discordUserId: session.discordUserId,
            eventType: 'session_expired',
            severity: 'info',
            description: `Expired session attempted for use`,
            metadata: { expiresAt: session.expiresAt }
          });
          return;
        }

        // Check if session is already used
        if (session.used) {
          result.error = 'Session already used';
          await this.logReplayAttempt(tx, session, context, 'token_reuse');
          return;
        }

        // Validate session binding if enabled
        if (this.config.sessionBindingEnabled && session.bindingHash) {
          if (session.bindingHash !== contextHash) {
            result.error = 'Session binding violation';
            await this.logSecurityEvent(tx, {
              sessionId: session.id,
              discordUserId: session.discordUserId,
              eventType: 'binding_violation',
              severity: 'high',
              description: 'Session used from different context than created',
              metadata: { 
                expectedBinding: session.bindingHash, 
                actualBinding: contextHash,
                context: context 
              }
            });
            
            // Do not invalidate the session yet - log the violation
            return;
          }
        }

        // Check for replay attempts based on timing
        const timeSinceCreation = Date.now() - new Date(session.createdAt).getTime();
        if (timeSinceCreation < 1000) { // Less than 1 second
          await this.logReplayAttempt(tx, session, context, 'timing_anomaly');
          result.error = 'Timing anomaly detected';
          return;
        }

        // Session is valid - atomically invalidate it
        session.used = true;
        session.lastUsedAt = new Date();
        session.usageCount = (session.usageCount || 0) + 1;
        session.lastContextHash = contextHash;

        await tx.write('verification-sessions.json', sessions);

        // Log successful session usage
        await this.logSecurityEvent(tx, {
          sessionId: session.id,
          discordUserId: session.discordUserId,
          eventType: 'session_invalidated',
          severity: 'info',
          description: 'Session successfully validated and invalidated',
          metadata: { 
            token: session.token.substring(0, 8),
            usageCount: session.usageCount,
            contextHash 
          }
        });

        result = {
          valid: true,
          sessionId: session.id,
          discordUserId: session.discordUserId,
          error: undefined
        };
      });

      return result;

    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error('Error during session validation:', err);
      return {
        valid: false,
        error: `Session validation failed: ${err.message}`
      };
    }
  }

  /**
   * Detect session replay attempts and track suspicious activity
   */
  async detectReplayAttempts(sessionId: string, context: SessionBinding): Promise<{
    isReplay: boolean;
    reason?: string;
    shouldBlock: boolean;
  }> {
    const contextHash = this.generateBindingHash(context);

    try {
      let result: { isReplay: boolean; reason?: string; shouldBlock: boolean } = { isReplay: false, shouldBlock: false };

      await databaseDriver.executeTransaction(['verification-sessions.json'], async (tx: any) => {
        const sessions = await tx.read('verification-sessions.json');
        const session = sessions.find((s: any) => s.id === sessionId);

        if (!session) {
          result = { isReplay: true, reason: 'Session not found', shouldBlock: true };
          return;
        }

        const now = Date.now();
        // const sessionAge = now - new Date(session.createdAt).getTime(); // Unused variable removed

        // Check for rapid reuse attempts
        if (session.lastUsedAt) {
          const timeSinceLastUse = now - new Date(session.lastUsedAt).getTime();
          if (timeSinceLastUse < this.config.replayDetectionWindow) {
            await this.logReplayAttempt(tx, session, context, 'token_reuse');
            result = { isReplay: true, reason: 'Rapid token reuse', shouldBlock: true };
            return;
          }
        }

        // Check for context mismatch
        if (session.bindingHash && session.bindingHash !== contextHash) {
          await this.logReplayAttempt(tx, session, context, 'context_mismatch');
          result = { isReplay: true, reason: 'Context mismatch', shouldBlock: true };
          return;
        }

        // Check for geographic anomalies (basic implementation)
        if (session.lastIpAddress && context.ipAddress &&
            session.lastIpAddress !== context.ipAddress) {
          // Simple distance-based check could be implemented here
          await this.logReplayAttempt(tx, session, context, 'geographic_anomaly');
          result = { isReplay: true, reason: 'Geographic anomaly', shouldBlock: true };
          return;
        }

        result = { isReplay: false, shouldBlock: false };
      });

      return result;

    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error('Error detecting replay attempts:', err);
      return { isReplay: false, shouldBlock: false };
    }
  }

  /**
   * Clean up expired sessions and perform security maintenance
   */
  async performSecurityCleanup(): Promise<{
    expiredSessions: number;
    compromisedSessions: number;
    replayAttempts: number;
    errors: string[];
  }> {
    const errors: string[] = [];
    let expiredSessions = 0;
    let compromisedSessions = 0;
    let replayAttempts = 0;

    try {
      await databaseDriver.executeTransaction(['verification-sessions.json'], async (tx: any) => {
        const sessions = await tx.read('verification-sessions.json');
        const now = new Date();

        const updatedSessions = [];
        
        for (const session of sessions) {
          const sessionObj = session as any;
          let shouldRemove = false;
          // let removalReason = ''; // Unused variable removed

          // Check if session is expired
          if (now > new Date(sessionObj.expiresAt)) {
            expiredSessions++;
            shouldRemove = true;
            // removalReason = 'expired';

            await this.logSecurityEvent(tx, {
              sessionId: sessionObj.id,
              discordUserId: sessionObj.discordUserId,
              eventType: 'session_expired',
              severity: 'info',
              description: `Session expired and cleaned up`,
              metadata: { 
                expiresAt: sessionObj.expiresAt,
                createdAt: sessionObj.createdAt,
                usageCount: sessionObj.usageCount 
              }
            });
          }

          // Check for compromised sessions (too many usage attempts)
          else if ((sessionObj.usageCount || 0) > 10) {
            compromisedSessions++;
            shouldRemove = true;
            // removalReason = 'compromised';

            await this.logSecurityEvent(tx, {
              sessionId: sessionObj.id,
              discordUserId: sessionObj.discordUserId,
              eventType: 'security_alert',
              severity: 'critical',
              description: `Session flagged as compromised due to excessive usage`,
              metadata: { 
                usageCount: sessionObj.usageCount,
                lastUsedAt: sessionObj.lastUsedAt 
              }
            });
          }

          // Check for suspicious replay patterns
          const recentReplayAttempts = this.getRecentReplayAttempts(sessionObj.id, now);
          if (recentReplayAttempts.length >= this.config.maxReplayAttempts) {
            replayAttempts += recentReplayAttempts.length;
            shouldRemove = true;
            // removalReason = 'replay_patterns';

            await this.logSecurityEvent(tx, {
              sessionId: sessionObj.id,
              discordUserId: sessionObj.discordUserId,
              eventType: 'security_alert',
              severity: 'high',
              description: `Session removed due to multiple replay attempts`,
              metadata: { 
                replayAttempts: recentReplayAttempts.length,
                recentAttempts: recentReplayAttempts 
              }
            });
          }

          if (!shouldRemove) {
            updatedSessions.push(sessionObj);
          }
        }

        await tx.write('verification-sessions.json', updatedSessions);
      });

      logger.info(`Security cleanup completed: ${expiredSessions} expired, ${compromisedSessions} compromised, ${replayAttempts} replay attempts`);

    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      errors.push(`Cleanup failed: ${err.message}`);
      logger.error('Security cleanup failed:', err);
    }

    return {
      expiredSessions,
      compromisedSessions,
      replayAttempts,
      errors
    };
  }

  /**
   * Generate session binding hash for context validation
   */
  private generateBindingHash(binding: SessionBinding): string {
    const bindingData = JSON.stringify({
      ipAddress: binding.ipAddress,
      userAgent: binding.userAgent,
      guildId: binding.guildId,
      verificationType: binding.verificationType,
      deviceFingerprint: binding.deviceFingerprint
    });

    return createHash('sha256').update(bindingData).digest('hex');
  }

  /**
   * Log a security event with audit trail
   */
  private async logSecurityEvent(tx: DatabaseTransaction, event: Omit<SessionSecurityEvent, 'id' | 'timestamp'>): Promise<void> {
    try {
      const securityEvents = await tx.read('session-security-events.json');
      
      securityEvents.push({
        id: randomBytes(16).toString('hex'),
        timestamp: new Date(),
        ...event
      });

      // Keep only recent events to prevent file growth
      if (securityEvents.length > 10000) {
        securityEvents.splice(0, securityEvents.length - 10000);
      }

      await tx.write('session-security-events.json', securityEvents);
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error('Failed to log security event:', err);
    }
  }

  /**
   * Log a replay attempt for detection and prevention
   */
  private async logReplayAttempt(
    tx: DatabaseTransaction,
    session: any,
    context: SessionBinding,
    reason: SessionReplayAttempt['detectionReason']
  ): Promise<void> {
    try {
      const replayAttempts = await tx.read('session-replay-attempts.json');
      
      const contextHash = this.generateBindingHash(context);
      const severity = this.calculateReplaySeverity(reason);

      replayAttempts.push({
        id: randomBytes(16).toString('hex'),
        sessionId: session.id,
        token: session.token,
        discordUserId: session.discordUserId,
        attemptTimestamp: new Date(),
        contextHash,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        detectionReason: reason,
        severity,
        blocked: severity === 'critical'
      });

      await tx.write('session-replay-attempts.json', replayAttempts);

      logger.warn(`Session replay attempt detected: ${reason}`, {
        sessionId: session.id,
        discordUserId: session.discordUserId,
        severity,
        reason
      });

    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error('Failed to log replay attempt:', err);
    }
  }

  /**
   * Calculate replay attempt severity based on detection reason
   */
  private calculateReplaySeverity(reason: SessionReplayAttempt['detectionReason']): SessionReplayAttempt['severity'] {
    switch (reason) {
      case 'token_reuse':
        return 'critical';
      case 'context_mismatch':
        return 'high';
      case 'geographic_anomaly':
        return 'medium';
      case 'timing_anomaly':
        return 'low';
      default:
        return 'medium';
    }
  }

  /**
   * Get recent replay attempts for a session
   */
  private getRecentReplayAttempts(_sessionId: string, _now: Date): any[] {
    // This would typically read from the replay attempts log
    // For now, return empty array as this is a simplified implementation
    return [];
  }

  /**
   * Get session security statistics
   */
  async getSessionSecurityStats(): Promise<{
    totalSessions: number;
    activeSessions: number;
    expiredSessions: number;
    compromisedSessions: number;
    replayAttempts: number;
    bindingViolations: number;
    securityEvents: number;
  }> {
    try {
      const sessions = await databaseDriver.readFile('verification-sessions.json');
      const replayAttempts = await databaseDriver.readFile('session-replay-attempts.json');
      const securityEvents = await databaseDriver.readFile('session-security-events.json');

      const now = new Date();
      
      const stats = {
        totalSessions: sessions.length,
        activeSessions: sessions.filter((s: any) => 
          !s.used && new Date(s.expiresAt) > now
        ).length,
        expiredSessions: sessions.filter((s: any) => 
          new Date(s.expiresAt) <= now
        ).length,
        compromisedSessions: sessions.filter((s: any) => 
          (s.usageCount || 0) > 10
        ).length,
        replayAttempts: replayAttempts.length,
        bindingViolations: securityEvents.filter((e: any) => 
          e.eventType === 'binding_violation'
        ).length,
        securityEvents: securityEvents.length
      };

      return stats;

    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error('Failed to get session security stats:', err);
      return {
        totalSessions: 0,
        activeSessions: 0,
        expiredSessions: 0,
        compromisedSessions: 0,
        replayAttempts: 0,
        bindingViolations: 0,
        securityEvents: 0
      };
    }
  }
}

// Export singleton instance
export const sessionSecurityManager = new SessionSecurityManager();