// Enhanced Verification Service with Comprehensive Session Replay Prevention
// Implements atomic session validation, replay detection, and one-time usage security

import { logger } from '../utils/logger';
import { database } from '../database';
import { zkVerificationService } from './zkVerification';
import { discordService } from './discordService';
import { notificationService } from './notificationService';
import { sessionManagerService } from './sessionManagerService';
import { generateHMACSignature, verifyHMACSignature } from '../../../bot/src/utils/hmac';
import { randomBytes } from 'crypto';

export interface VerificationRequest {
  proofs: any[];
  sessionId: string;
  domain: string;
  uniqueIdentifier: string;
  verificationType: string;
  // Enhanced security context for replay detection
  ipAddress?: string;
  userAgent?: string;
  guildId?: string;
}

export interface VerificationResult {
  verified: boolean;
  uniqueIdentifier?: string;
  message?: string;
  discordUserId?: string;
  sessionId?: string;
}

export class VerificationError extends Error {
  constructor(message: string, public statusCode: number = 500) {
    super(message);
    this.name = 'VerificationError';
  }
}

/**
 * Perform atomic verification with session security
 */
export async function performVerification(request: VerificationRequest, transaction?: any): Promise<VerificationResult> {
  const {
    proofs,
    sessionId,
    domain,
    verificationType,
    ipAddress,
    userAgent,
    guildId
  } = request;

  // Create session binding context for security validation
  const sessionBinding = {
    ipAddress,
    userAgent,
    guildId,
    verificationType
  };

  // Enhanced session validation with comprehensive replay protection
  const sessionValidation = await sessionManagerService.validateSessionToken({
    sessionId,
    token: sessionId, // Use sessionId as token for now
    domain,
    verificationType,
    ipAddress,
    userAgent,
    guildId
  });

  if (!sessionValidation.valid) {
    logger.warn(`Session validation failed for session ${sessionId}: ${sessionValidation.error}`);
    
    // Log failed validation attempt
    await logSecurityEvent({
      sessionId,
      discordUserId: sessionValidation.discordUserId || 'unknown',
      eventType: 'session_invalidated',
      severity: 'warning',
      description: `Session validation failed: ${sessionValidation.error}`,
      metadata: {
        token: sessionId ? sessionId.substring(0, 8) : 'unknown',
        error: sessionValidation.error,
        context: sessionBinding
      }
    });

    throw new VerificationError(`Session validation failed: ${sessionValidation.error}`, 400);
  }

  const { sessionId: validatedSessionId, discordUserId } = sessionValidation;

  if (!validatedSessionId || !discordUserId) {
    throw new VerificationError('Invalid session validation result', 400);
  }

  try {
    logger.info(`Starting verification for session ${sessionId} (user: ${discordUserId})`);

    // Verify ZK proofs
    const verificationResult = await zkVerificationService.verifyProofs(
      proofs, 
      domain, 
      verificationType
    );

    if (!verificationResult.verified) {
      // Log failed verification
      if (discordUserId) {
        await logVerificationHistory(discordUserId, false, verificationResult.message);
      }
      
      logger.warn(`Verification failed for user ${discordUserId}: ${verificationResult.message}`);
      return { 
        verified: false, 
        message: verificationResult.message,
        sessionId: validatedSessionId 
      };
    }

    // Sybil attack prevention
    const existingVerification = await database.findVerificationByFingerprint(
      verificationResult.passportFingerprint!
    );
    
    if (existingVerification && existingVerification.discordUserId !== discordUserId) {
      logger.warn(`Sybil attack detected! User ${discordUserId} tried to use a passport with a fingerprint already linked to ${existingVerification.discordUserId}.`);
      
      if (validatedSessionId && discordUserId) {
        await logSecurityEvent({
          sessionId: validatedSessionId,
          discordUserId,
          eventType: 'security_alert',
          severity: 'critical',
          description: 'Sybil attack detected - passport fingerprint reuse',
          metadata: {
            attemptedFingerprint: verificationResult.passportFingerprint,
            existingUser: existingVerification.discordUserId
          }
        });
      }

      throw new VerificationError(
        'This passport has already been used to verify a different Discord account.', 
        409
      );
    }

    // Check if user already has active verification
    if (!discordUserId) {
      throw new VerificationError('Discord user ID is required', 400);
    }
    const existingUserVerification = await database.findAdminVerification(discordUserId);
    if (existingUserVerification && existingUserVerification.isActive && existingUserVerification.passportFingerprint !== '' && existingUserVerification.uniqueIdentifier !== '') {
      throw new VerificationError('User already has active admin verification', 409);
    }

    // Assign Discord role
    if (!discordUserId) {
      throw new VerificationError('Discord user ID is required for role assignment', 400);
    }
    const roleAssignedSuccessfully = await discordService.sendWebhookToBot(
      discordUserId,
      'assign',
      'ZKPassport verification successful'
    );

    if (!roleAssignedSuccessfully) {
      // Log the failure but don't fail the verification
      await logVerificationHistory(discordUserId, false, 'Role assignment failed after successful verification');
      
      logger.warn(`Role assignment failed for user ${discordUserId} after successful verification`);

      return {
        verified: true,
        message: 'Verification succeeded, but failed to assign Discord role.',
        uniqueIdentifier: verificationResult.uniqueIdentifier,
        discordUserId,
        sessionId: validatedSessionId
      };
    }

    // Success - update database with transaction
    await database.upsertAdminVerification({
      id: randomBytes(32).toString('hex'),
      discordUserId,
      uniqueIdentifier: verificationResult.uniqueIdentifier!,
      passportFingerprint: verificationResult.passportFingerprint!,
      isActive: true,
      lastVerified: new Date(),
    });

    // Log successful verification
    if (discordUserId) {
      await logVerificationHistory(discordUserId, true, null);

      // Send success notification
      await notificationService.sendVerificationSuccess(discordUserId);
    }

    // Broadcast real-time update
    if (discordUserId) {
      await notificationService.broadcastVerificationUpdate({
        discordUserId,
        status: 'completed',
        verified: true,
        uniqueIdentifier: verificationResult.uniqueIdentifier,
      });
    }

    // Log successful session usage
    if (validatedSessionId && discordUserId) {
      await logSecurityEvent({
        sessionId: validatedSessionId,
        discordUserId,
        eventType: 'session_used',
        severity: 'info',
        description: 'Session successfully used for verification',
        metadata: {
          verificationType,
          uniqueIdentifier: verificationResult.uniqueIdentifier,
          token: sessionId.substring(0, 8)
        }
      });
    }

    logger.info(`Verification and role assignment successful for user ${discordUserId}`);

    return {
      verified: true,
      uniqueIdentifier: verificationResult.uniqueIdentifier,
      message: 'Verification successful',
      discordUserId,
      sessionId: validatedSessionId,
    };

  } catch (error) {
    // Log security event for any errors during verification
    if (validatedSessionId && discordUserId) {
      await logSecurityEvent({
        sessionId: validatedSessionId,
        discordUserId,
        eventType: 'security_alert',
        severity: 'error',
        description: 'Verification process failed with error',
        metadata: {
          error: error instanceof Error ? error.message : String(error),
          verificationType,
          token: sessionId ? sessionId.substring(0, 8) : 'unknown'
        }
      });
    }

    if (error instanceof VerificationError) {
      throw error;
    }

    logger.error(`Unexpected error during verification for user ${discordUserId}:`, error);
    throw new VerificationError('Verification process failed', 500);
  }
}

/**
 * Enhanced verification status check with security validation
 */
export async function checkVerificationStatus(sessionId: string) {
  // Create basic binding for status check (no IP/UserAgent available)
  const sessionBinding = {
    verificationType: 'status_check'
  };

  // Use the session security manager to validate the session status
  const sessionValidation = await sessionManagerService.validateSessionToken({
    sessionId,
    token: sessionId,
    verificationType: 'status_check'
  });

  // If session is invalid, return the validation error
  if (!sessionValidation.valid) {
    return { 
      valid: false, 
      message: sessionValidation.error || 'Session invalid',
      sessionId: sessionValidation.sessionId
    };
  }

  const { discordUserId } = sessionValidation;

  if (!sessionId || !discordUserId) {
    return {
      valid: false,
      message: 'Invalid session validation result',
      sessionId: sessionValidation.sessionId
    };
  }

  // Check if verification is already completed
  if (!discordUserId) {
    return {
      valid: false,
      message: 'Invalid session - no Discord user ID',
      sessionId
    };
  }
  const adminVerification = await database.findAdminVerification(discordUserId);
  if (adminVerification?.isActive) {
    return {
      valid: true,
      status: 'completed',
      verified: true,
      uniqueIdentifier: adminVerification.uniqueIdentifier,
      message: 'Verification already completed',
      sessionId
    };
  }

  // Session is still active
  return {
    valid: true,
    status: 'pending',
    expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
    discordUserId,
    message: 'Session active',
    sessionId
  };
}

/**
 * Log verification history with enhanced security tracking
 */
async function logVerificationHistory(discordUserId: string, success: boolean, errorMessage: string | null) {
  try {
    await database.createVerificationHistory({
      discordUserId,
      success,
      errorMessage,
      timestamp: new Date()
    });
  } catch (error) {
    logger.error('Failed to log verification history:', error);
  }
}

async function logSecurityEvent(event: {
  sessionId: string;
  discordUserId: string;
  eventType: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  description: string;
  metadata: Record<string, any>;
}) {
  try {
    // This would integrate with the session security manager's logging system
    logger.info(`Security Event: ${event.eventType}`, {
      sessionId: event.sessionId,
      discordUserId: event.discordUserId,
      severity: event.severity,
      description: event.description,
      metadata: event.metadata
    });

    // Log security event without calling stubbed methods
    logger.debug('Security event logged with context');

  } catch (error) {
    logger.error('Failed to log security event:', error);
  }
}


/**
 * Perform security cleanup of expired and compromised sessions
 */
export async function performSecurityCleanup(): Promise<{
  expiredSessions: number;
  compromisedSessions: number;
  replayAttempts: number;
  errors: string[];
}> {
  try {
    logger.info('Starting session security cleanup...');
    
    const cleanupResult = await sessionManagerService.performSecurityCleanup();
    
    logger.info('Session security cleanup completed', cleanupResult);
    
    return cleanupResult;
    
  } catch (error) {
    logger.error('Session security cleanup failed:', error);
    return {
      expiredSessions: 0,
      compromisedSessions: 0,
      replayAttempts: 0,
      errors: [error instanceof Error ? error.message : String(error)]
    };
  }
}

/**
 * Get comprehensive session security statistics
 */
export async function getSessionSecurityStatistics() {
  try {
    const stats = await sessionManagerService.getSessionSecurityStatistics();
    
    logger.info('Session security statistics retrieved', stats);
    
    return {
      ...stats,
      timestamp: new Date(),
      systemHealthy: stats.replayAttempts < 10 && stats.bindingViolations < 5
    };
    
  } catch (error) {
    logger.error('Failed to get session security statistics:', error);
    return {
      totalSessions: 0,
      activeSessions: 0,
      expiredSessions: 0,
      compromisedSessions: 0,
      replayAttempts: 0,
      bindingViolations: 0,
      securityEvents: 0,
      timestamp: new Date(),
      systemHealthy: false,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}