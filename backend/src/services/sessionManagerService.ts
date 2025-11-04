// Session Manager Service for Discord ZK Verification
// Handles session creation, validation, and security token management

import { logger } from '../utils/logger';
import { database } from '../database';
import { enhancedSessionSecurityManager } from '../../../bot/src/utils/enhancedSessionSecurity';
import { randomBytes } from 'crypto';

export const sessionManagerService = {
  createVerificationSession,
  validateSessionToken,
  invalidateSession,
  getSessionSecurityStatistics,
  performSecurityCleanup
};

export interface CreateSessionRequest {
  discordUserId: string;
  domain?: string;
  verificationType?: string;
  ipAddress?: string;
  userAgent?: string;
  guildId?: string;
}

export interface CreateSessionResponse {
  sessionId: string;
  token: string;
  expiresAt: Date;
}

export interface ValidateSessionRequest {
  sessionId: string;
  token?: string;
  domain?: string;
  verificationType?: string;
  ipAddress?: string;
  userAgent?: string;
  guildId?: string;
}

export interface ValidateSessionResponse {
  valid: boolean;
  discordUserId?: string;
  sessionId?: string;
  error?: string;
}

export class SessionError extends Error {
  constructor(message: string, public statusCode: number = 500) {
    super(message);
    this.name = 'SessionError';
  }
}

/**
 * Create a new verification session with security bindings
 */
export async function createVerificationSession(request: CreateSessionRequest): Promise<CreateSessionResponse> {
  try {
    const {
      discordUserId,
      domain,
      verificationType,
      ipAddress,
      userAgent,
      guildId
    } = request;

    logger.info(`Creating verification session for user ${discordUserId}`);

    // Create session binding context
    const binding = {
      ipAddress,
      userAgent,
      guildId,
      verificationType,
      timestamp: Date.now()
    };

    // Use enhanced security manager to create session
    const sessionResult = await enhancedSessionSecurityManager.createEnhancedSecureSession(
      discordUserId,
      binding,
      undefined, // fingerprint
      new Date(Date.now() + 15 * 60 * 1000) // 15 minutes
    );

    logger.info(`Verification session created for user ${discordUserId}: ${sessionResult.sessionId}`);

    return {
      sessionId: sessionResult.sessionId,
      token: sessionResult.token,
      expiresAt: sessionResult.expiresAt
    };

  } catch (error) {
    logger.error('Failed to create verification session:', error);
    throw new SessionError('Session creation failed', 500);
  }
}

/**
 * Validate a session token and binding context
 */
export async function validateSessionToken(request: ValidateSessionRequest): Promise<ValidateSessionResponse> {
  try {
    const {
      sessionId,
      token,
      domain,
      verificationType,
      ipAddress,
      userAgent,
      guildId
    } = request;

    logger.debug(`Validating session token for session ${sessionId}`);

    // Create validation binding context
    const binding = {
      token,
      ipAddress,
      userAgent,
      guildId,
      verificationType,
      timestamp: Date.now()
    };

    // Validate session using enhanced security manager
    const validationResult = await enhancedSessionSecurityManager.validateAndInvalidateSession(
      sessionId,
      binding,
      {
        domain,
        verificationType,
        timestamp: Date.now(),
        ipAddress,
        userAgent
      }
    );

    if (!validationResult.valid) {
      logger.warn(`Session validation failed for session ${sessionId}: ${validationResult.error}`);
      return {
        valid: false,
        sessionId: validationResult.sessionId,
        error: validationResult.error
      };
    }

    logger.info(`Session validation successful for session ${sessionId}, user ${validationResult.discordUserId}`);

    return {
      valid: true,
      discordUserId: validationResult.discordUserId,
      sessionId: validationResult.sessionId
    };

  } catch (error) {
    logger.error('Session validation error:', error);
    return {
      valid: false,
      sessionId: request.sessionId,
      error: 'Session validation failed'
    };
  }
}

/**
 * Invalidate a session (mark as used)
 */
export async function invalidateSession(sessionId: string): Promise<boolean> {
  try {
    logger.info(`Invalidating session ${sessionId}`);

    // Find the session
    const session = await database.findVerificationSession(sessionId);
    if (!session) {
      logger.warn(`Session ${sessionId} not found for invalidation`);
      return false;
    }

    // Mark session as used/invalidated
    await database.updateVerificationSession(sessionId, { used: true });

    logger.info(`Session ${sessionId} invalidated successfully`);
    return true;

  } catch (error) {
    logger.error(`Failed to invalidate session ${sessionId}:`, error);
    return false;
  }
}

/**
 * Get session security statistics
 */
export async function getSessionSecurityStatistics() {
  try {
    // Get stats from enhanced security manager
    return await enhancedSessionSecurityManager.getSessionSecurityStats();
  } catch (error) {
    logger.error('Failed to get session security statistics:', error);
    return {
      totalSessions: 0,
      activeSessions: 0,
      expiredSessions: 0,
      compromisedSessions: 0,
      replayAttempts: 0,
      bindingViolations: 0,
      timestamp: new Date(),
      systemHealthy: false
    };
  }
}

/**
 * Perform security cleanup of expired sessions
 */
export async function performSecurityCleanup(): Promise<{
  expiredSessions: number;
  compromisedSessions: number;
  replayAttempts: number;
  errors: string[];
}> {
  try {
    logger.info('Starting session security cleanup via session manager');

    const cleanupResult = await enhancedSessionSecurityManager.performSecurityCleanup();

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