import { Request, Response, NextFunction } from 'express';
import { prisma } from '../utils/database';
import { logger } from '../utils/logger';
import { auditLogger } from '@shared/services/auditLogger';

interface AuthenticatedRequest extends Request {
  userId?: string;
  sessionId?: string;
  discordUserId?: string;
}

interface TokenValidationResult {
  valid: boolean;
  sessionId?: string;
  discordUserId?: string;
  expiresAt?: Date;
  message?: string;
}

/**
 * Validate verification token and session
 */
export async function validateToken(token: string): Promise<TokenValidationResult> {
  try {
    if (!token) {
      return {
        valid: false,
        message: 'Token is required',
      };
    }

    // Find session by id (sessionId is passed as token parameter)
    const session = await prisma.verificationSession.findUnique({
      where: { id: token },
    });

    if (!session) {
      logger.warn('Verification session not found', { token: token.substring(0, 8) + '...' });
      return {
        valid: false,
        message: 'Session not found',
      };
    }

    // Check if session is expired
    if (session.expiresAt < new Date()) {
      logger.info('Expired verification session accessed', {
        sessionId: session.id,
        discordUserId: session.discordUserId
      });
      return {
        valid: false,
        message: 'Session expired',
      };
    }

    // Check if session was already used
    if (session.used) {
      logger.info('Used verification session accessed', {
        sessionId: session.id,
        discordUserId: session.discordUserId
      });
      return {
        valid: false,
        message: 'Session already used',
      };
    }

    return {
      valid: true,
      sessionId: session.id,
      discordUserId: session.discordUserId,
      expiresAt: session.expiresAt,
    };

  } catch (error) {
    logger.error('Token validation error:', error);
    return {
      valid: false,
      message: 'Token validation failed',
    };
  }
}

/**
 * Express middleware to validate verification token
 */
export async function requireValidToken(req: Request, res: Response, next: NextFunction) {
  const token = req.body.token || req.query.token;

  if (!token) {
    return res.status(401).json({
      error: 'Token required',
      message: 'Verification token is required',
    });
  }

  try {
    const result = await validateToken(token);
    if (!result.valid) {
      return res.status(401).json({
        error: 'Invalid token',
        message: result.message || 'Token validation failed',
      });
    }

    // Add user info to request object
    (req as AuthenticatedRequest).sessionId = result.sessionId;
    (req as AuthenticatedRequest).discordUserId = result.discordUserId;

    next();
  } catch (error) {
    logger.error('Token validation middleware error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Token validation failed',
    });
  }
}

/**
 * Express middleware to check if user is already verified
 */
export async function checkVerificationStatus(req: Request, res: Response, next: NextFunction) {
  try {
    const discordUserId = (req as AuthenticatedRequest).discordUserId;

    if (!discordUserId) {
      return res.status(400).json({
        error: 'User ID not found',
        message: 'Discord user ID is required',
      });
    }

    // Check if user already has active verification
    const existingVerification = await prisma.adminVerification.findUnique({
      where: { discordUserId },
    });

    if (existingVerification && existingVerification.isActive) {
      return res.status(409).json({
        error: 'Already verified',
        message: 'User already has active admin verification',
        uniqueIdentifier: existingVerification.uniqueIdentifier,
      });
    }

    next();

  } catch (error) {
    logger.error('Verification status check error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to check verification status',
    });
  }
}

/**
 * Rate limiting for verification attempts
 */
const verificationAttempts = new Map<string, { count: number; resetTime: number }>();

export function checkVerificationRateLimit(discordUserId: string, maxAttempts: number = 3): boolean {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes

  if (!verificationAttempts.has(discordUserId) || now > verificationAttempts.get(discordUserId)!.resetTime) {
    // Reset or initialize attempt counter
    verificationAttempts.set(discordUserId, {
      count: 0,
      resetTime: now + windowMs,
    });
  }

  const userAttempts = verificationAttempts.get(discordUserId)!;

  if (userAttempts.count >= maxAttempts) {
    // Log rate limit exceeded using the new secure method
    auditLogger.logSecurityEvent('rate_limit_exceeded', {
      attempts: userAttempts.count,
      maxAttempts,
      resetTime: new Date(userAttempts.resetTime).toISOString(),
      ipAddress: 'system' // Note: IP not available here, could be added if passed in
    }, discordUserId);

    logger.warn(`Rate limit exceeded for user ${discordUserId}`, {
      attempts: userAttempts.count,
      maxAttempts,
      resetTime: new Date(userAttempts.resetTime),
    });
    return false;
  }

  // Increment the counter only if the limit hasn't been exceeded
  userAttempts.count++;
  return true;
}

/**
 * Clean up expired rate limit entries
 */
export function cleanupRateLimitEntries(): void {
  const now = Date.now();
  for (const [userId, attempts] of verificationAttempts.entries()) {
    if (now > attempts.resetTime) {
      verificationAttempts.delete(userId);
    }
  }
}

/**
 * Clear rate limit map for testing (only use in test environment)
 */
export function clearRateLimitMapForTesting(): void {
  if (process.env.NODE_ENV === 'test') {
    verificationAttempts.clear();
  }
}

// Clean up rate limit entries every 5 minutes
let rateLimitCleanupInterval: NodeJS.Timeout | null = null;

export function startRateLimitCleanup(): void {
  if (!rateLimitCleanupInterval) {
    rateLimitCleanupInterval = setInterval(cleanupRateLimitEntries, 5 * 60 * 1000);
  }
}

export function stopRateLimitCleanup(): void {
  if (rateLimitCleanupInterval) {
    clearInterval(rateLimitCleanupInterval);
    rateLimitCleanupInterval = null;
  }
}

// Do NOT start cleanup automatically in test environment
if (process.env.NODE_ENV !== 'test') {
  startRateLimitCleanup();
}