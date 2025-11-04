import { Router, Request, Response } from 'express';
import { logger } from '../utils/logger';
import { performVerification, checkVerificationStatus, VerificationError } from '../services/verificationService';
import { validateVerificationRequest, verificationProofSchema, verificationWebhookSchema, verificationStatusSchema } from '../services/validationService';
import { zkVerificationService } from '../services/zkVerification';
import { database } from '../database';
import { enhancedSessionSecurityManager } from '../../../bot/src/utils/enhancedSessionSecurity';
import { discordService } from '../services/discordService';
import { notificationService } from '../services/notificationService';
import { getEnabledTypes } from '@shared/config/verification.js';
import { validateAndSanitize, validateParams } from '../middleware/auth';
import { checkVerificationState, VerificationStateError } from '../services/verificationStateService';

const router = Router();

// Simple rate limiting for verification endpoints
const verificationRateLimitMap = new Map<string, { count: number; resetTime: number }>();

function verificationRateLimit(req: any, res: any, next: any) {
  const now = Date.now();
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const key = `verification_${ip}`;
  
  const limit = verificationRateLimitMap.get(key);
  if (!limit || now > limit.resetTime) {
    verificationRateLimitMap.set(key, { count: 1, resetTime: now + 60000 }); // 1 minute window
    next();
    return;
  }
  
  if (limit.count >= 10) { // 10 requests per minute for verification
    res.status(429).json({ error: 'Rate limit exceeded' });
    return;
  }
  
  limit.count++;
  next();
}

// Service rate limiting for webhook endpoint
const webhookRateLimitMap = new Map<string, { count: number; resetTime: number }>();

function webhookRateLimit(req: any, res: any, next: any) {
  const now = Date.now();
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const key = `webhook_${ip}`;
  
  const limit = webhookRateLimitMap.get(key);
  if (!limit || now > limit.resetTime) {
    webhookRateLimitMap.set(key, { count: 1, resetTime: now + 60000 }); // 1 minute window
    next();
    return;
  }
  
  if (limit.count >= 100) { // 100 requests per minute for webhooks
    res.status(429).json({ error: 'Rate limit exceeded' });
    return;
  }
  
  limit.count++;
  next();
}

router.post('/proof',
  verificationRateLimit,
  validateAndSanitize(verificationProofSchema),
  async (req: Request, res: Response) => {
    try {
      const { proofs, sessionId, token, domain, verificationType } = req.body;

      // Phase 1: All Async Reads and External Validations (BEFORE the transaction)
      const sessionBinding = {
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('user-agent'),
        guildId: req.body.guildId,
        verificationType,
        token
      };

      // Verify ZK proofs
      const verificationResult = await zkVerificationService.verifyProofs(
        proofs,
        domain,
        verificationType
      );

      if (!verificationResult.verified || !verificationResult.uniqueIdentifier || !verificationResult.passportFingerprint) {
        await database.createVerificationHistory({
          discordUserId: null, // Allow null for failed verifications before user identification
          success: false,
          errorMessage: verificationResult.message || 'Verification failed or identifiers were not returned.',
          timestamp: new Date()
        });
        logger.warn(`Verification failed: ${verificationResult.message}`);
        return res.status(400).json({
          verified: false,
          message: verificationResult.message,
          sessionId
        });
      }

      // Retrieve session and get discordUserId for state-aware verification
      const session = await database.findVerificationSession(sessionId);
      if (!session) {
        return res.status(404).json({ verified: false, message: "Verification session not found." });
      }
      const discordUserId = session.discordUserId;

      // Check verification state using the new service
      const verificationStateDecision = await checkVerificationState(discordUserId, verificationResult.passportFingerprint);

      // Phase 2: All Critical Database Operations (INSIDE the atomic transaction)
      const result = await database.executeTransaction(['verification-sessions', 'admin-verifications', 'verification-history'], async (tx: any) => {
        // 1. Find and validate the session within the transaction
        const session = await tx.verificationSession.findUnique({
          where: { id: sessionId }
        });

        if (!session) throw new VerificationError('Session not found', 404);
        if (session.used) throw new VerificationError('Session already used', 409);
        if (session.expiresAt < new Date()) throw new VerificationError('Session expired', 410);

        const discordUserId = session.discordUserId;

        // 2. Invalidate the session
        await tx.verificationSession.update({
          where: { id: sessionId },
          data: { used: true, lastUsedAt: new Date() }
        });

        // 3. Upsert the user's verification status
        const updatedVerification = await tx.adminVerification.upsert({
          where: { discordUserId: discordUserId },
          update: {
            uniqueIdentifier: verificationResult.uniqueIdentifier,
            passportFingerprint: verificationResult.passportFingerprint,
            lastVerified: new Date(),
            isActive: true,
          },
          create: {
            discordUserId: discordUserId,
            uniqueIdentifier: verificationResult.uniqueIdentifier,
            passportFingerprint: verificationResult.passportFingerprint,
            lastVerified: new Date(),
            isActive: true,
          }
        });

        // 4. Log successful verification
        await tx.verificationHistory.create({
          data: {
            discordUserId: discordUserId,
            success: true,
          }
        });

        return {
            verified: true,
            uniqueIdentifier: updatedVerification.uniqueIdentifier,
            message: 'Verification successful',
            discordUserId: updatedVerification.discordUserId,
            sessionId,
        };
      });

      // Phase 3: Post-transaction operations (e.g., Discord role assignment)
      const roleAssignedSuccessfully = await discordService.sendWebhookToBot(
        result.discordUserId,
        'assign',
        'ZKPassport verification successful'
      );

      if (!roleAssignedSuccessfully) {
        logger.warn(`Role assignment failed for user ${result.discordUserId} after successful verification.`);
        // Optionally, log this failure to the history table in a separate, non-blocking call
      }

      res.json({ ...result, message: roleAssignedSuccessfully ? result.message : 'Verification succeeded, but failed to assign Discord role.' });

    } catch (error) {
      logger.error('Verification route error:', { error });
      if (error instanceof VerificationStateError) {
        return res.status(error.statusCode).json({
          verified: false,
          message: error.message,
          sessionId: req.body.sessionId
        });
      }
      if (error instanceof VerificationError) {
        return res.status(error.statusCode).json({
          verified: false,
          message: error.message,
        });
      }
      return res.status(500).json({
        verified: false,
        message: 'An internal error occurred during verification.',
      });
    }
  }
);

router.get('/status/:token',
  verificationRateLimit,
  validateParams(verificationStatusSchema),
  async (req: Request, res: Response) => {
    try {
      const { token } = req.params;
      const status = await checkVerificationStatus(token);
      res.json(status);
    } catch (error) {
      logger.error('Status check error:', error);

      res.status(500).json({
        valid: false,
        message: process.env.NODE_ENV === 'production' ? 'An error occurred' : 'Internal server error',
      });
    }
  }
);

router.post('/webhook',
  webhookRateLimit,
  validateAndSanitize(verificationWebhookSchema),
  async (req: Request, res: Response) => {
    try {
      const { discordUserId, status, uniqueIdentifier } = req.body;

      if (!discordUserId || !status) {
        return res.status(400).json({
          error: 'Missing required fields: discordUserId, status',
        });
      }

      logger.info(`Verification webhook received for user ${discordUserId}: ${status}`);

      // Import notificationService dynamically to avoid circular dependency
      const { notificationService } = await import('../services/notificationService');

      // Broadcast real-time update
      notificationService.broadcastVerificationUpdate({
        discordUserId,
        status,
        verified: status === 'completed',
        uniqueIdentifier,
      });

      // Send Discord notification
      if (status === 'completed') {
        await notificationService.sendVerificationSuccess(discordUserId);
      }

      res.json({ success: true });

    } catch (error) {
      logger.error('Webhook error:', error);

      res.status(500).json({
        error: process.env.NODE_ENV === 'production' ? 'An error occurred' : 'Internal server error',
      });
    }
  }
);

export default router;