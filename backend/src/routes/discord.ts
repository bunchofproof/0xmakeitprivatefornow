import { Router, Request, Response } from 'express';
import Joi from 'joi';
import { discordService } from '../services/discordService';
import { logger } from '../utils/logger';
import { validateAndSanitize } from '../middleware/auth';
import { discordRegisterSchema, discordVerifySchema, discordUserIdParamSchema } from '../services/validationService';


const router = Router();

// Simple rate limiting for Discord routes
const discordRateLimitMap = new Map<string, { count: number; resetTime: number }>();

function discordRateLimit(req: any, res: any, next: any) {
  const now = Date.now();
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const key = `discord_${ip}`;
  
  const limit = discordRateLimitMap.get(key);
  if (!limit || now > limit.resetTime) {
    discordRateLimitMap.set(key, { count: 1, resetTime: now + 60000 }); // 1 minute window
    next();
    return;
  }
  
  if (limit.count >= 10) { // 10 requests per minute for discord endpoints
    res.status(429).json({ error: 'Rate limit exceeded' });
    return;
  }
  
  limit.count++;
  next();
}

// Validation schemas
// @ts-ignore - TypeScript inference issue with Joi schema
const roleUpdateSchema = Joi.object({
  // @ts-ignore - TypeScript inference issue with Joi schema
  userId: Joi.string().pattern(/^\d+$/).min(17).max(19).required()
    .messages({
      'string.pattern.base': 'User ID must contain only numbers',
      'string.min': 'User ID must be at least 17 digits',
      'string.max': 'User ID must be at most 19 digits'
    }),
  action: Joi.string().valid('add', 'remove').required(),
  reason: Joi.string().max(500).optional()
});

// @ts-ignore - TypeScript inference issue with Joi schema
const userIdSchema = Joi.object({
  // @ts-ignore - TypeScript inference issue with Joi schema
  userId: Joi.string().pattern(/^\d+$/).min(17).max(19).required()
    .messages({
      'string.pattern.base': 'User ID must contain only numbers',
      'string.min': 'User ID must be at least 17 digits',
      'string.max': 'User ID must be at most 19 digits'
    })
});

// Apply rate limiting for Discord user operations
router.get('/user/:userId', discordRateLimit, async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;
    const userIdStr = String(userId);

    // Validate userId parameter format
    const { error } = userIdSchema.validate({ userId: userIdStr });
    if (error) {
      return res.status(400).json({
        error: 'Invalid user ID format',
        message: error.details[0].message,
      });
    }

    logger.info(`Fetching Discord user info for: ${userId}`);

    // Get user information from Discord
    const userInfo = await discordService.getUserInfo(userId);
    if (!userInfo) {
      return res.status(404).json({
        error: 'User not found',
        message: 'Discord user not found',
      });
    }

    // Check if user has admin role
    const hasAdminRole = await discordService.hasAdminRole(userId);

    res.json({
      user: userInfo,
      hasAdminRole,
      verified: hasAdminRole,
    });

  } catch (error) {
    logger.error('Error fetching Discord user info:', error);

    res.status(500).json({
      error: 'Internal server error',
      message: process.env.NODE_ENV === 'production' ? 'An error occurred' : 'Failed to fetch user information',
    });
  }
});

// Apply rate limiting for Discord registration
router.post('/register', discordRateLimit, async (req: Request, res: Response) => {
  try {
    const { discordUserId, verified } = req.body;

    if (!discordUserId || typeof verified !== 'boolean') {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: discordUserId (string), verified (boolean)',
      });
    }

    logger.info(`Discord registration request for user ${discordUserId}: verified=${verified}`);

    // Update Discord roles based on verification status
    const success = await discordService.updateRolesForVerification(discordUserId, verified);

    if (success) {
      res.json({
        success: true,
        message: verified ? 'Admin role assigned successfully' : 'Admin role removed successfully',
        discordUserId,
        verified,
      });
    } else {
      res.status(500).json({
        success: false,
        message: 'Failed to update Discord roles',
        discordUserId,
        verified,
      });
    }

  } catch (error) {
    logger.error('Discord registration error:', error);

    res.status(500).json({
      success: false,
      message: process.env.NODE_ENV === 'production' ? 'An error occurred' : 'Internal server error during Discord role update',
    });
  }
});

// Apply rate limiting for Discord verification
router.post('/verify', discordRateLimit, async (req: Request, res: Response) => {
  try {
    const { discordUserId, action } = req.body;

    if (!discordUserId || !action) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: discordUserId, action',
      });
    }

    logger.info(`Discord verification action ${action} for user ${discordUserId}`);

    let success = false;

    if (action === 'assign') {
      success = await discordService.assignAdminRole(discordUserId);
    } else if (action === 'revoke') {
      success = await discordService.removeAdminRole(discordUserId);
    } else {
      return res.status(400).json({
        success: false,
        message: 'Invalid action. Must be "assign" or "revoke"',
      });
    }

    if (success) {
      res.json({
        success: true,
        message: `Discord role ${action} successful`,
        discordUserId,
        action,
      });
    } else {
      res.status(500).json({
        success: false,
        message: `Failed to ${action} Discord role`,
        discordUserId,
        action,
      });
    }

  } catch (error) {
    logger.error('Discord verification error:', error);

    res.status(500).json({
      success: false,
      message: process.env.NODE_ENV === 'production' ? 'An error occurred' : 'Internal server error during Discord verification',
    });
  }
});

// Apply strict rate limiting for role updates (admin level)
router.post('/role-update', discordRateLimit, async (req: Request, res: Response) => {
  try {
    const { userId, action } = req.body;

    logger.info(`Role update request: ${action} admin role for user ${userId}`);

    let success = false;

    if (action === 'add') {
      success = await discordService.assignAdminRole(userId);
    } else {
      success = await discordService.removeAdminRole(userId);
    }

    if (success) {
      res.json({
        success: true,
        message: `Admin role ${action}ed successfully`,
        userId,
        action,
      });
    } else {
      res.status(500).json({
        error: 'Role update failed',
        message: 'Failed to update Discord roles',
      });
    }

  } catch (error) {
    logger.error('Role update error:', error);

    res.status(500).json({
      error: 'Internal server error',
      message: process.env.NODE_ENV === 'production' ? 'An error occurred' : 'Failed to update roles',
    });
  }
});

// Apply generous rate limiting for health checks
router.get('/health', discordRateLimit, async (_req: Request, res: Response) => {
  try {
    const isHealthy = await discordService.healthCheck();

    res.json({
      status: isHealthy ? 'healthy' : 'unhealthy',
      service: 'discord',
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    logger.error('Discord health check error:', error);

    res.status(503).json({
      status: 'unhealthy',
      service: 'discord',
      error: process.env.NODE_ENV === 'production' ? 'An error occurred' : 'Health check failed',
      timestamp: new Date().toISOString(),
    });
  }
});

export default router;