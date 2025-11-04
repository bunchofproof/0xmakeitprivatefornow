import express from 'express';
import rateLimit from 'express-rate-limit';
import Joi from 'joi';
import { logger } from '../utils/logger';
import { verifySecureHMACSignature, getHMACSecret } from '../utils/hmac';
import { botDiscordService } from '../services/discordService';
import { BotAuditLogger } from '../utils/botAuditLogger';

interface RoleUpdateRequest {
  userId: string;
  action: 'assign' | 'revoke';
  reason?: string;
  requestId?: string;
}

// Validation schemas
const roleUpdateSchema = Joi.object({
  userId: Joi.string().alphanum().min(1).max(20).required()
    .messages({
      'string.empty': 'userId cannot be empty',
      'string.min': 'userId must be at least 1 character long',
      'string.max': 'userId must be at most 20 characters long',
      'any.required': 'userId is required'
    }),
  action: Joi.string().valid('assign', 'revoke').required()
    .messages({
      'any.only': 'Action must be either "assign" or "revoke"',
      'any.required': 'action is required'
    }),
  reason: Joi.string().max(500).optional()
    .messages({
      'string.max': 'Reason must be at most 500 characters long'
    }),
  requestId: Joi.string().uuid().optional()
    .messages({
      'string.uuid': 'requestId must be a valid UUID'
    })
});

// Validation middleware
const validateRoleUpdateRequest = (req: any, res: any, next: any) => {
  const { error } = roleUpdateSchema.validate(req.body, { abortEarly: false });
  if (error) {
    logger.warn('Invalid role update request', {
      errors: error.details.map(detail => detail.message),
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    return res.status(400).json({
      error: 'Validation failed',
      message: 'Request validation failed',
      details: error.details.map(detail => detail.message)
    });
  }
  next();
};

let webhookServer: any = null;
let webhookPort: number = 3001; // Default port, can be configured

export async function setupWebhookServer(): Promise<void> {
  const app = express();

  // Request size limits (FIRST - before any processing)
  app.use(express.json({ limit: '500kb' }));
  app.use(express.urlencoded({ limit: '500kb', extended: true }));

  // Rate limiting configuration
  const rateLimitWindowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MINUTES || '15') * 60 * 1000;
  const rateLimitMaxRequests = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100');

  // General rate limiter for all requests
  const generalLimiter = rateLimit({
    windowMs: rateLimitWindowMs,
    max: rateLimitMaxRequests,
    message: {
      error: 'Too many requests',
      message: 'Rate limit exceeded. Please try again later.',
    },
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Stricter rate limiter for sensitive endpoints (admin commands)
  const strictLimiter = rateLimit({
    windowMs: rateLimitWindowMs,
    max: 100, // Allow 100 requests per 15 minutes for development
    message: {
      error: 'Too many admin requests',
      message: 'Rate limit exceeded for admin operations. Please try again later.',
    },
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Apply general rate limiter to all routes
  app.use(generalLimiter);

  // Enhanced HMAC signature verification middleware with replay protection
  app.use('/api/webhooks', (req: any, res: any, next: any) => {
    try {
      const signature = req.headers['x-signature-256'];
      const timestamp = req.headers['x-timestamp'];
      const nonce = req.headers['x-nonce'];

      if (!signature) {
        logger.warn('Webhook request missing HMAC signature', {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          endpoint: req.path,
        });

        BotAuditLogger.logSecurityViolation('system', 'unauthorized_webhook_access', {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          endpoint: req.path,
          reason: 'missing_signature',
        });

        return res.status(401).json({
          error: 'Unauthorized',
          message: 'X-Signature-256 header is required',
        });
      }

      // Verify HMAC signature with replay protection
      const { valid, error } = verifySecureHMACSignature(
        req.body,
        signature,
        getHMACSecret(),
        timestamp as string,
        nonce as string
      );

      if (!valid) {
        logger.warn('Unauthorized webhook request - invalid or replayed HMAC signature', {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          endpoint: req.path,
          hasTimestamp: !!timestamp,
          hasNonce: !!nonce,
          nonce: nonce ? nonce.toString().substring(0, 8) + '...' : 'none',
          error
        });

        BotAuditLogger.logSecurityViolation('system', 'unauthorized_webhook_access', {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          endpoint: req.path,
          reason: error || 'invalid_hmac_signature',
          hasTimestamp: !!timestamp,
          hasNonce: !!nonce,
          nonce: nonce ? nonce.toString().substring(0, 8) + '...' : 'none',
        });

        return res.status(401).json({
          error: 'Unauthorized',
          message: error || 'Invalid HMAC signature',
        });
      }

      logger.info('Secure webhook request validated successfully', {
        ip: req.ip,
        endpoint: req.path,
        hasTimestamp: !!timestamp,
        hasNonce: !!nonce,
        nonce: nonce ? nonce.toString().substring(0, 8) + '...' : 'none',
      });

      next();
    } catch (error) {
      logger.error('HMAC verification failed', undefined, {
        error: error instanceof Error ? error.message : String(error),
        ip: req.ip,
      } as Record<string, any>);
      return res.status(500).json({
        error: 'Internal server error',
        message: 'Signature verification failed',
      });
    }
  });

  // Health check endpoint with secure HMAC verification and replay protection
  app.get('/health', (req: any, res: any) => {
    try {
      const signature = req.headers['x-signature-256'];
      const timestamp = req.headers['x-timestamp'];
      const nonce = req.headers['x-nonce'];
      
      // If a signature is provided, verify it securely (for backend health checks)
      if (signature) {
        const healthPayload = {
          service: 'backend',
          type: 'health_check'
        };
        
        const { valid, error } = verifySecureHMACSignature(
          healthPayload,
          signature,
          getHMACSecret(),
          timestamp as string,
          nonce as string
        );
        
        if (!valid) {
          logger.warn('Unauthorized health check request - invalid or replayed HMAC signature', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            hasTimestamp: !!timestamp,
            hasNonce: !!nonce,
            error
          });

          BotAuditLogger.logSecurityViolation('system', 'unauthorized_health_check', {
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            reason: 'invalid_hmac_signature',
          });

          return res.status(401).json({
            error: 'Unauthorized',
            message: 'Invalid HMAC signature',
          });
        }
      }
      
      res.json({
        status: 'healthy',
        service: 'discord-bot-webhook',
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('Health check HMAC verification failed', undefined, {
        error: error instanceof Error ? error.message : String(error),
        ip: req.ip,
      } as Record<string, any>);
      return res.status(500).json({
        error: 'Internal server error',
        message: 'Health check verification failed',
      });
    }
  });

  // Role management webhook endpoint (stricter rate limiting for sensitive operations)
  app.post('/api/webhooks/role-update', strictLimiter, validateRoleUpdateRequest, async (req: any, res: any) => {
    const { userId, action, reason, requestId }: RoleUpdateRequest = req.body;

    logger.info('Processing role update request', {
      action,
      userId,
      reason,
      requestId,
      ip: req.ip,
    });

    logger.debug(`Webhook payload received: userId=${userId}, action=${action}, reason=${reason}, requestId=${requestId}`);

    // Await the result from the service
    const success = await processRoleUpdate(userId, action, reason, requestId);

    logger.info('Role update result', {
      action,
      userId,
      success,
    });

    if (success) {
      // If the service returned true, send 200 OK
      return res.status(200).json({ success: true, message: 'Role assigned successfully.' });
    } else {
      // If the service returned false, send 500 Internal Server Error
      logger.error('Role update failed', undefined, {
        action,
        userId,
      } as Record<string, any>);
      return res.status(500).json({ success: false, message: 'Bot failed to assign Discord role.' });
    }
  });

  // Start server
  webhookPort = parseInt(process.env.BOT_WEBHOOK_PORT || '3001');

  return new Promise((resolve, reject) => {
    webhookServer = app.listen(webhookPort, () => {
      logger.info('Webhook server listening', {
        port: webhookPort,
      });
      resolve();
    });

    webhookServer.on('error', (error: any) => {
      logger.error('Failed to start webhook server', undefined, {
        error: error instanceof Error ? error.message : String(error),
      } as Record<string, any>);
      reject(error);
    });
  });
}

async function processRoleUpdate(
  userId: string,
  action: 'assign' | 'revoke',
  reason?: string,
  requestId?: string
): Promise<boolean> {
  const maxRetries = 3;
  const retryDelay = 1000; // 1 second

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      logger.info('Attempting role update', {
        action,
        attempt,
        maxRetries,
        userId,
      });

      let success: boolean;

      if (action === 'assign') {
        success = await botDiscordService.assignAdminRole(userId);
      } else {
        success = await botDiscordService.removeAdminRole(userId);
      }

      if (success) {
        // Log successful role change
        BotAuditLogger.logRoleChange('system', 'system', action === 'assign' ? 'assignment' : 'removal', 'Admin Role', {
          userId,
          reason: reason || `Role ${action} via webhook`,
          requestId,
          attempt,
        });

        return true; // <--- Return true on success
      } else {
        throw new Error(`Discord service returned false for ${action} operation`);
      }

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      logger.warn('Role update attempt failed', {
        action,
        attempt,
        maxRetries,
        userId,
        errorMessage,
      });

      // Log failed attempt
      BotAuditLogger.logSecurityViolation('system', `role_${action}_failed`, {
        userId,
        attempt,
        maxRetries,
        error: errorMessage,
        requestId,
      });

      if (attempt === maxRetries) {
        logger.error('Failed to assign role after all retries', undefined, {
          userId,
          action,
          maxRetries,
        } as Record<string, any>);
        return false; // <--- Return false on final failure
      }

      // Wait before retry
      await new Promise(resolve => setTimeout(resolve, retryDelay * attempt));
    }
  }

  return false; // <--- Return false if max retries exceeded
}

export function getWebhookPort(): number {
  return webhookPort;
}

export function shutdownWebhookServer(): Promise<void> {
  return new Promise((resolve) => {
    if (webhookServer) {
      webhookServer.close(() => {
        logger.info('Webhook server shut down');
        resolve();
      });
    } else {
      resolve();
    }
  });
}

// Graceful shutdown handler
process.on('SIGTERM', async () => {
  logger.info('Received SIGTERM, shutting down webhook server');
  await shutdownWebhookServer();
});

process.on('SIGINT', async () => {
  logger.info('Received SIGINT, shutting down webhook server');
  await shutdownWebhookServer();
});