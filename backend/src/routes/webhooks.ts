import { Router, Request, Response } from 'express';
import { notificationService } from '../services/notificationService';
import { logger } from '../utils/logger';
import { webhookDiscordSchema, webhookVerificationSchema, webhookHealthSchema } from '../services/validationService';
import { validateAndSanitize } from '../middleware/auth';

const router = Router();

// Simple webhook rate limiting
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
  
  if (limit.count >= 1000) { // 1000 requests per minute for webhooks
    res.status(429).json({ error: 'Rate limit exceeded' });
    return;
  }
  
  limit.count++;
  next();
}

// POST /api/webhooks/discord - Handle Discord bot webhooks
router.post('/discord',
  webhookRateLimit,
  validateAndSanitize(webhookDiscordSchema),
  async (req: Request, res: Response) => {
    try {
      const { type, data, userId } = req.body;

      if (!type || !data) {
        return res.status(400).json({
          error: 'Missing required fields',
          message: 'type and data are required',
        });
      }

      logger.info(`Discord webhook received: ${type}`, { userId });

      // Handle different webhook types
      switch (type) {
        case 'verification_started':
          await handleVerificationStarted(data, userId);
          break;

        case 'verification_completed':
          await handleVerificationCompleted(data, userId);
          break;

        case 'verification_failed':
          await handleVerificationFailed(data, userId);
          break;

        case 'role_updated':
          await handleRoleUpdated(data, userId);
          break;

        default:
          logger.warn(`Unknown Discord webhook type: ${type}`);
      }

      res.json({ success: true, received: true });

    } catch (error) {
      logger.error('Discord webhook error:', error);

      res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'production' ? 'An error occurred' : 'Webhook processing failed',
      });
    }
  }
);

// POST /api/webhooks/verification - Handle verification status updates
router.post('/verification',
  webhookRateLimit,
  validateAndSanitize(webhookVerificationSchema),
  async (req: Request, res: Response) => {
    try {
      const { sessionId, status, userId, metadata } = req.body;

      if (!sessionId || !status || !userId) {
        return res.status(400).json({
          error: 'Missing required fields',
          message: 'sessionId, status, and userId are required',
        });
      }

      logger.info(`Verification webhook: ${status} for session ${sessionId}`, { userId });

      // Broadcast real-time update
      notificationService.broadcastVerificationUpdate({
        discordUserId: userId,
        status,
        timestamp: new Date(),
      });

      // Handle specific status updates
      switch (status) {
        case 'completed':
          await notificationService.sendVerificationSuccess(userId);
          break;

        case 'failed':
          await notificationService.sendVerificationFailure(userId, metadata?.reason);
          break;
      }

      res.json({ success: true });

    } catch (error) {
      logger.error('Verification webhook error:', error);

      res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'production' ? 'An error occurred' : 'Verification webhook processing failed',
      });
    }
  }
);

// POST /api/webhooks/health - Health check webhook for monitoring
router.post('/health',
  webhookRateLimit,
  validateAndSanitize(webhookHealthSchema),
  async (req: Request, res: Response) => {
    try {
      const { service, status, timestamp } = req.body;

      logger.info(`Health webhook received: ${service} - ${status}`);

      // Broadcast health status update
      notificationService.broadcast({
        type: 'health_update',
        service,
        status,
        timestamp: timestamp || new Date().toISOString(),
      });

      res.json({ success: true });

    } catch (error) {
      logger.error('Health webhook error:', error);

      res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'production' ? 'An error occurred' : 'Health webhook processing failed',
      });
    }
  }
);

/**
 * Handle verification started event
 */
async function handleVerificationStarted(_data: any, userId: string) {
  notificationService.broadcastVerificationUpdate({
    discordUserId: userId,
    status: 'pending',
    timestamp: new Date(),
  });
}

/**
 * Handle verification completed event
 */
async function handleVerificationCompleted(data: any, userId: string) {
  notificationService.broadcastVerificationUpdate({
    discordUserId: userId,
    status: 'completed',
    verified: true,
    uniqueIdentifier: data.uniqueIdentifier,
    timestamp: new Date(),
  });
}

/**
 * Handle verification failed event
 */
async function handleVerificationFailed(_data: any, userId: string) {
  notificationService.broadcastVerificationUpdate({
    discordUserId: userId,
    status: 'failed',
    verified: false,
    timestamp: new Date(),
  });
}

/**
 * Handle role updated event
 */
async function handleRoleUpdated(data: any, userId: string) {
  notificationService.broadcast({
    type: 'role_update',
    userId,
    roleId: data.roleId,
    action: data.action,
    timestamp: new Date().toISOString(),
  });
}

export default router;