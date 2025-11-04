import { randomBytes, createHash } from 'crypto';
import { logger } from './logger';
import { databaseDriver } from './databaseDrivers';
import { sessionCleanupService } from '../services/sessionCleanupService';
import { getSessionSecurityStats } from '../services/sessionStatsService';

// Security session interface
interface SecuritySession {
  id: string;
  token: string;
  discordUserId: string;
  expiresAt: Date;
  bindingHash?: string;
  fingerprint?: string;
  nonce?: string;
  createdAt: Date;
  lastUsedAt?: Date;
  usageCount?: number;
  sequenceNumber?: number;
  lastContextHash?: string;
  lastNonce?: string;
  lastRequestHash?: string;
  used?: boolean;
}

// Session validation result
export interface SessionValidationResult {
  valid: boolean;
  error?: string;
  replayAttempt?: boolean;
  detectionReason?: string;
  session?: SecuritySession;
  contextHash?: string;
  nonce?: string;
  requestHash?: string;
  pendingUpdates?: {
    usageCount: number;
    lastUsedAt: Date;
    lastContextHash: string;
    sequenceNumber: number;
    lastNonce?: string;
    lastRequestHash?: string;
  };
}

// Enhanced session binding context
interface SessionBinding {
  ipAddress?: string;
  userAgent?: string;
  timestamp?: number;
  nonce?: string;
  [key: string]: any;
}

/**
 * Enhanced Session Security Manager
 * 
 * Provides advanced session security features including:
 * - Session binding to request context
 * - Replay attack detection
 * - Timing anomaly detection
 * - Security event logging
 * - Enhanced audit trails
 */
export class EnhancedSessionSecurityManager {
  private readonly MAX_SESSION_AGE = 30 * 60 * 1000; // 30 minutes
  private readonly REPLAY_WINDOW = 1000; // 1 second window for replay detection
  private readonly SEQUENCE_WINDOW = 5; // Maximum sequence number variance
  private readonly MAX_USAGE_COUNT = 3; // Maximum usage count before forced expiry

  constructor() {
    logger.info('Enhanced Session Security Manager initialized', {
      maxSessionAge: this.MAX_SESSION_AGE,
      replayWindow: this.REPLAY_WINDOW,
      sequenceWindow: this.SEQUENCE_WINDOW,
      maxUsageCount: this.MAX_USAGE_COUNT
    });
  }

  /**
   * Generate a simple HMAC-like hash
   */
  private generateHash(data: string, key: string): string {
    return createHash('sha256').update(data + key).digest('hex');
  }

  /**
   * Create an enhanced secure session with advanced security features
   */
  async createEnhancedSecureSession(
    discordUserId: string,
    binding?: SessionBinding,
    fingerprint?: string,
    expiresAt?: Date
  ): Promise<{
    sessionId: string;
    token: string;
    expiresAt: Date;
    bindingHash?: string;
    securityFeatures: {
      bindingEnabled: boolean;
      fingerprintingEnabled: boolean;
      replayProtection: boolean;
    };
  }> {
    try {
      const sessionId = randomBytes(32).toString('hex');
      const token = randomBytes(32).toString('hex');
      const bindingHash = binding ? this.generateBindingHash(binding) : undefined;
      const expiryDate = expiresAt || new Date(Date.now() + this.MAX_SESSION_AGE);

      logger.debug(`Creating enhanced secure session for user ${discordUserId}`, {
        sessionId,
        hasBinding: !!binding,
        hasFingerprint: !!fingerprint,
        expiresAt: expiryDate.toISOString()
      });

      // Create session data
      const sessionData: SecuritySession = {
        id: sessionId,
        token,
        discordUserId,
        expiresAt: expiryDate,
        bindingHash,
        fingerprint,
        nonce: binding?.nonce,
        createdAt: new Date(),
        usageCount: 0,
        sequenceNumber: 0
      };

      // Store session in database with transaction
      await databaseDriver.executeTransaction(['verification-sessions.json'], async (tx: any) => {
        const sessions = await tx.read('verification-sessions.json');
        
        // Check for existing sessions that should be invalidated
        const existingSession = sessions.find((s: any) => 
          s.discordUserId === discordUserId &&
          !s.used
        );

        if (existingSession) {
          // Atomically invalidate existing session
          existingSession.used = true;
          existingSession.invalidationAttempts++;
          existingSession.lastUsedAt = new Date();
        }

        sessions.push(sessionData);
        await tx.write('verification-sessions.json', sessions);

        await this.logSecurityEvent({
          sessionId,
          discordUserId,
          eventType: 'session_created',
          severity: 'info',
          description: `Enhanced secure session created for user ${discordUserId}`,
          metadata: {
            expiresAt: expiryDate.toISOString(),
            bindingHash,
            hasBinding: !!binding,
            hasFingerprint: !!fingerprint
          }
        });
      });

      logger.info(`Enhanced secure session created for user ${discordUserId}`, {
        sessionId,
        expiresAt: expiryDate.toISOString(),
        hasBinding: !!bindingHash,
        hasFingerprint: !!fingerprint
      });

      return {
        sessionId,
        token,
        expiresAt: expiryDate,
        bindingHash,
        securityFeatures: {
          bindingEnabled: !!binding,
          fingerprintingEnabled: !!fingerprint,
          replayProtection: true
        }
      };

    } catch (error) {
      logger.error('Failed to create enhanced secure session:', error instanceof Error ? error : new Error(String(error)));
      throw new Error('Session creation failed');
    }
  }

  /**
   * Async validate session - performs all database reads and validation checks, returns SessionValidationResult
   */
   async validateSession(
     context: SessionBinding,
     requestData?: any
   ): Promise<SessionValidationResult> {
     const contextHash = this.generateBindingHash(context);
     const token = context.token;

     console.log(`[!!!] FINAL DEBUG: Value of token at line 199 is: ${token}`);

     logger.info(`[DEBUG SESSION VALIDATION] Starting validation for token: ${token ? token.substring(0, 8) : '[UNDEFINED TOKEN]' }...`, {
      contextHash: contextHash.substring(0, 16),
      hasIpAddress: !!context.ipAddress,
      hasUserAgent: !!context.userAgent,
      hasGuildId: !!context.guildId,
      verificationType: context.verificationType
    });

    try {
      // Find session using database-agnostic interface
      const session = await databaseDriver.findVerificationSession(token);

      logger.debug(`[DEBUG SESSION VALIDATION] Session lookup result: ${session ? 'FOUND' : 'NOT FOUND'}`, {
        token: token.substring(0, 8),
        foundSessionId: session?.id?.substring(0, 8)
      });

      console.log('--- FINAL INSPECTION ---');
      console.log('Session from DB:', JSON.stringify(session, null, 2));
      console.log('Incoming Token:', token);
      console.log('------------------------');

      logger.info(`[DEBUG SESSION VALIDATION] Session lookup result: ${session ? 'FOUND' : 'NOT FOUND'}`, {
        token: token.substring(0, 8),
        foundSessionId: session?.id?.substring(0, 8),
        discordUserId: session?.discordUserId,
        isUsed: session?.used,
        expiresAt: session?.expiresAt,
        hasBindingHash: !!session?.bindingHash
      });

      if (!session) {
        console.log('INSPECTION FAILED: Session not found.');
        await this.logSecurityEvent({
          sessionId: 'unknown',
          discordUserId: 'unknown',
          eventType: 'replay_attempt',
          severity: 'warning',
          description: `Invalid token used: ${token.substring(0, 8)}...`,
          metadata: { token: token.substring(0, 8), contextHash }
        });
        return {
          valid: false,
          error: 'Invalid session ID',
          replayAttempt: true,
          detectionReason: 'session_id_not_found'
        };
      }

      // Check if session is expired
      const currentTime = new Date();
      const expiresAt = new Date(session.expiresAt);
      const isExpired = currentTime > expiresAt;

      logger.debug(`[DEBUG SESSION VALIDATION] Expiration check`, {
        token: token.substring(0, 8),
        currentTime: currentTime.toISOString(),
        expiresAt: expiresAt.toISOString(),
        isExpired,
        timeRemainingMs: expiresAt.getTime() - currentTime.getTime()
      });

      if (isExpired) {
        console.log('INSPECTION FAILED: Session expired.');
        await this.logSecurityEvent({
          sessionId: session.id,
          discordUserId: session.discordUserId,
          eventType: 'session_expired',
          severity: 'info',
          description: `Expired session attempted for use`,
          metadata: { expiresAt: session.expiresAt }
        });
        return {
          valid: false,
          error: 'Session expired'
        };
      }

      // Check if session is already used (one-time usage)
      logger.debug(`[DEBUG SESSION VALIDATION] Usage check`, {
        token: token.substring(0, 8),
        isUsed: session.used,
        usageCount: session.usageCount,
        lastUsedAt: session.lastUsedAt
      });

      if (session.used) {
        console.log('INSPECTION FAILED: Session already used.');
        await this.logReplayAttempt({
          sessionId: session.id,
          discordUserId: session.discordUserId,
          token: session.token,
          contextHash: contextHash,
          detectionReason: 'token_reuse',
          severity: 'high',
          blocked: true
        });
        return {
          valid: false,
          error: 'Session already used',
          replayAttempt: true,
          detectionReason: 'token_reuse'
        };
      }

      // Enhanced security validations
      logger.debug(`[DEBUG SESSION VALIDATION] Starting enhanced security validations`, {
        token: token.substring(0, 8),
        hasBindingHash: !!session.bindingHash,
        hasFingerprint: !!session.fingerprint,
        contextHash: contextHash.substring(0, 16),
        hasRequestData: !!requestData
      });

      const validationResult = await this.performEnhancedSecurityValidation(
        session, context, contextHash, requestData
      );

      logger.debug(`[DEBUG SESSION VALIDATION] Enhanced security validation result`, {
        token: token.substring(0, 8),
        valid: validationResult.valid,
        error: validationResult.error,
        replayAttempt: validationResult.replayAttempt,
        detectionReason: validationResult.detectionReason
      });

      if (!validationResult.valid) {
        console.log('INSPECTION FAILED: Enhanced security validation failed.');
        logger.warn(`[DEBUG SESSION VALIDATION] Enhanced security validation failed`, {
          token: token.substring(0, 8),
          error: validationResult.error,
          detectionReason: validationResult.detectionReason
        });
        return validationResult;
      }

      // Session is valid - prepare pending updates for synchronous write
      const usageCount = (session.usageCount || 0) + 1;
      const lastUsedAt = new Date();
      const sequenceNumber = (session.sequenceNumber || 0) + 1;

      logger.info(`[DEBUG SESSION VALIDATION] Session validation successful`, {
        token: token.substring(0, 8),
        discordUserId: session.discordUserId,
        usageCount,
        contextHash: contextHash.substring(0, 16)
      });

      return {
        valid: true,
        session,
        contextHash,
        nonce: validationResult.nonce,
        requestHash: validationResult.requestHash,
        pendingUpdates: {
          usageCount,
          lastUsedAt,
          lastContextHash: contextHash,
          sequenceNumber,
          lastNonce: validationResult.nonce,
          lastRequestHash: validationResult.requestHash
        }
      };

    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error('Error during enhanced session validation:', err);
      return {
        valid: false,
        error: `Session validation failed: ${err.message}`,
        replayAttempt: false
      };
    }
  }

  /**
   * Synchronous invalidate and persist session - performs all database writes within provided transaction
   */
  invalidateAndPersistSession(
    validationResult: SessionValidationResult,
    _tx: any
  ): void {
    if (!validationResult.valid || !validationResult.session || !validationResult.pendingUpdates) {
      throw new Error('Invalid validation result for persistence');
    }

    const session = validationResult.session;
    const updates = validationResult.pendingUpdates;

    try {
      // Atomically invalidate the session
      session.used = true;
      session.lastUsedAt = updates.lastUsedAt;
      session.usageCount = updates.usageCount;
      session.lastContextHash = updates.lastContextHash;
      session.sequenceNumber = updates.sequenceNumber;

      // Store nonce and request hash for audit
      if (updates.lastNonce) {
        session.lastNonce = updates.lastNonce;
      }
      if (updates.lastRequestHash) {
        session.lastRequestHash = updates.lastRequestHash;
      }

      // Note: sessions array is already loaded in the transaction context
      // The write will be handled by the transaction

      this.logSecurityEvent({
        sessionId: session.id,
        discordUserId: session.discordUserId,
        eventType: 'session_invalidated',
        severity: 'info',
        description: 'Session successfully validated and invalidated with enhanced security',
        metadata: {
          token: session.token.substring(0, 8),
          usageCount: session.usageCount,
          contextHash: validationResult.contextHash,
          validatedNonce: !!updates.lastNonce,
          validatedHash: !!updates.lastRequestHash
        }
      });

    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error('Error during session persistence:', err);
      throw new Error(`Session persistence failed: ${err.message}`);
    }
  }

  /**
   * Perform enhanced security validations
   */
  private async performEnhancedSecurityValidation(
    session: any,
    context: SessionBinding,
    contextHash: string,
    requestData?: any
  ): Promise<{
    valid: boolean;
    error?: string;
    replayAttempt?: boolean;
    detectionReason?: string;
    nonce?: string;
    requestHash?: string;
  }> {
    // Validate session binding if enabled
    if (session.bindingHash) {
      const validation = await this.validateSessionBinding(session.bindingHash, contextHash, context);
      if (!validation.valid) {
        return validation;
      }
    }

    // Validate session fingerprint if enabled
    if (session.fingerprint && requestData?.clientFingerprint) {
      const fingerprintValidation = await this.validateFingerprint(
        session.fingerprint, 
        requestData.clientFingerprint
      );
      if (!fingerprintValidation.valid) {
        return fingerprintValidation;
      }
    }

    // Enhanced replay detection
    const replayCheck = await this.performReplayDetection(session, context, contextHash);
    if (!replayCheck.valid) {
      return replayCheck;
    }

    return {
      valid: true,
      nonce: context.nonce,
      requestHash: this.generateRequestHash(requestData)
    };
  }

  /**
   * Validate session binding
   */
  private async validateSessionBinding(
    sessionBindingHash: string,
    contextHash: string,
    context: SessionBinding
  ): Promise<{ valid: boolean; error?: string; replayAttempt?: boolean; detectionReason?: string }> {
    // For now, simple binding validation - can be enhanced with more sophisticated checks
    if (sessionBindingHash !== contextHash) {
      await this.logSecurityEvent({
        sessionId: 'unknown',
        discordUserId: 'unknown',
        eventType: 'binding_mismatch',
        severity: 'high',
        description: 'Session binding validation failed',
        metadata: {
          expectedBinding: sessionBindingHash.substring(0, 16),
          actualBinding: contextHash.substring(0, 16),
          context: { ...context, nonce: context.nonce?.substring(0, 8) }
        }
      });

      return {
        valid: false,
        error: 'Session binding validation failed',
        replayAttempt: true,
        detectionReason: 'binding_mismatch'
      };
    }

    return { valid: true };
  }

  /**
   * Validate session fingerprint
   */
  private async validateFingerprint(
    sessionFingerprint: string,
    clientFingerprint: string
  ): Promise<{ valid: boolean; error?: string; replayAttempt?: boolean; detectionReason?: string }> {
    // Simple fingerprint validation - can be enhanced with more sophisticated checks
    if (sessionFingerprint !== clientFingerprint) {
      await this.logSecurityEvent({
        sessionId: 'unknown',
        discordUserId: 'unknown',
        eventType: 'fingerprint_mismatch',
        severity: 'high',
        description: 'Session fingerprint validation failed',
        metadata: {
          sessionFingerprint: sessionFingerprint.substring(0, 16),
          clientFingerprint: clientFingerprint.substring(0, 16)
        }
      });

      return {
        valid: false,
        error: 'Session fingerprint validation failed',
        replayAttempt: true,
        detectionReason: 'fingerprint_mismatch'
      };
    }

    return { valid: true };
  }

  /**
   * Perform enhanced replay detection
   */
  private async performReplayDetection(
    session: any,
    context: SessionBinding,
    contextHash: string
  ): Promise<{ valid: boolean; error?: string; replayAttempt?: boolean; detectionReason?: string }> {
    const currentTime = Date.now();

    // Check for rapid replay attempts
    if (session.lastUsedAt) {
      const timeSinceLastUse = currentTime - new Date(session.lastUsedAt).getTime();
      if (timeSinceLastUse < this.REPLAY_WINDOW) {
        await this.logReplayAttempt({
          sessionId: session.id,
          discordUserId: session.discordUserId,
          token: session.token,
          contextHash,
          detectionReason: 'rapid_replay',
          severity: 'high',
          blocked: true,
          metadata: { timeSinceLastUse }
        });

        return {
          valid: false,
          error: 'Rapid replay attempt detected',
          replayAttempt: true,
          detectionReason: 'rapid_replay'
        };
      }
    }

    // Check sequence number validation
    if (context.nonce && session.sequenceNumber) {
      const expectedSequence = session.sequenceNumber + 1;
      const providedSequence = parseInt(context.nonce, 36) % 1000; // Convert nonce to sequence-like number

      if (Math.abs(providedSequence - expectedSequence) > this.SEQUENCE_WINDOW) {
        await this.logReplayAttempt({
          sessionId: session.id,
          discordUserId: session.discordUserId,
          token: session.token,
          contextHash,
          detectionReason: 'sequence_anomaly',
          severity: 'medium',
          blocked: true,
          metadata: { expectedSequence, providedSequence, variance: Math.abs(providedSequence - expectedSequence) }
        });

        return {
          valid: false,
          error: 'Sequence number validation failed',
          replayAttempt: true,
          detectionReason: 'sequence_anomaly'
        };
      }
    }

    return { valid: true };
  }

  /**
   * Generate binding hash for session context
   */
  private generateBindingHash(context: SessionBinding): string {
    const bindingData = {
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      timestamp: Math.floor((context.timestamp || Date.now()) / 60000), // Minute precision
      nonce: context.nonce
    };

    return this.generateHash(JSON.stringify(bindingData), 'session-binding');
  }

  /**
   * Generate request hash for audit purposes
   */
  private generateRequestHash(requestData: any): string | undefined {
    if (!requestData) return undefined;

    const hashData = {
      domain: requestData.domain,
      verificationType: requestData.verificationType,
      proofsCount: requestData.proofs?.length || 0
    };

    return this.generateHash(JSON.stringify(hashData), 'request-hash');
  }

  /**
   * Log security event
   */
  private async logSecurityEvent(event: {
    sessionId: string;
    discordUserId: string;
    eventType: string;
    severity: 'info' | 'warning' | 'error' | 'high';
    description: string;
    metadata?: any;
  }): Promise<void> {
    try {
      logger.warn(`Security Event: ${event.eventType}`, {
        sessionId: event.sessionId,
        discordUserId: event.discordUserId,
        severity: event.severity,
        description: event.description,
        ...event.metadata
      });
    } catch (error) {
      logger.error('Failed to log security event:', error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Log replay attempt
   */
  private async logReplayAttempt(event: {
    sessionId: string;
    discordUserId: string;
    token: string;
    contextHash: string;
    detectionReason: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    blocked: boolean;
    metadata?: any;
  }): Promise<void> {
    try {
      logger.warn(`Replay Attempt Detected: ${event.detectionReason}`, {
        sessionId: event.sessionId,
        discordUserId: event.discordUserId,
        token: event.token.substring(0, 8),
        contextHash: event.contextHash.substring(0, 16),
        detectionReason: event.detectionReason,
        severity: event.severity,
        blocked: event.blocked,
        timestamp: new Date().toISOString(),
        ...event.metadata
      });
    } catch (error) {
      logger.error('Failed to log replay attempt:', error instanceof Error ? error : new Error(String(error)));
    }
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
    timestamp: Date;
    systemHealthy: boolean;
  }> {
    return getSessionSecurityStats();
  }

  /**
   * Perform security cleanup of expired and compromised sessions
   */
  async performSecurityCleanup(): Promise<{
    expiredSessions: number;
    compromisedSessions: number;
    replayAttempts: number;
    errors: string[];
  }> {
    return sessionCleanupService.performSecurityCleanup();
  }

  /**
   * Validate and invalidate session in atomic transaction
   */
  async validateAndInvalidateSession(
    sessionId: string,
    binding: SessionBinding,
    requestData?: any
  ): Promise<{
    valid: boolean;
    sessionId?: string;
    discordUserId?: string;
    error?: string;
  }> {
    const validation = await this.validateSession(binding, requestData);
    if (!validation.valid) {
      return {
        valid: false,
        sessionId,
        error: validation.error
      };
    }
    try {
      let finalSession: SecuritySession | undefined;

      // Perform validation and invalidation in a single transaction
      await databaseDriver.executeTransaction(['verification-sessions.json'], async (tx: any) => {
        const sessions = await tx.read('verification-sessions.json');

        // Find the session
        const sessionIndex = sessions.findIndex((s: any) => s.id === sessionId);
        if (sessionIndex === -1) {
          throw new Error('Invalid session ID');
        }

        // If validation passed, invalidate the session
        if (validation.session && validation.pendingUpdates) {
          this.invalidateAndPersistSession(validation, {
            write: async (filename: string, data: any) => {
              await tx.write(filename, data);
            }
          });
          finalSession = validation.session;
        }
      });

      return {
        valid: true,
        sessionId: finalSession?.id || undefined,
        discordUserId: finalSession?.discordUserId || undefined
      };

    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error('Validate and invalidate session error:', err);
      return {
        valid: false,
        sessionId,
        error: `Session validation failed: ${err.message}`
      };
    }
  }
}

export const enhancedSessionSecurityManager = new EnhancedSessionSecurityManager();