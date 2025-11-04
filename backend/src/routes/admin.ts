import { Router, Request, Response } from 'express';
import { validateApiKey } from '../middleware/auth';
import { discordService } from '../services/discordService';
import { notificationService } from '../services/notificationService';
import { databaseService } from '../utils/database';
import { logger } from '../utils/logger';
import { adminVerifyUserSchema, adminRevokeUserSchema } from '../services/validationService';
import { validateAndSanitize } from '../middleware/auth';


const router = Router();

// Apply API key authentication to all admin routes
router.use(validateApiKey);

// Admin rate limiting
const adminRateLimitMap = new Map<string, { count: number; resetTime: number }>();

function adminRateLimit(req: any, res: any, next: any) {
  const now = Date.now();
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const key = `admin_${ip}`;
  
  const limit = adminRateLimitMap.get(key);
  if (!limit || now > limit.resetTime) {
    adminRateLimitMap.set(key, { count: 1, resetTime: now + 60000 }); // 1 minute window
    next();
    return;
  }
  
  if (limit.count >= 5) { // 5 requests per minute for admin endpoints
    res.status(429).json({ error: 'Rate limit exceeded' });
    return;
  }
  
  limit.count++;
  next();
}

// GET /api/admin/stats - Get system statistics with rate limiting
router.get('/stats', adminRateLimit, async (_req: Request, res: Response) => {
    try {
      logger.info('Fetching admin statistics');

      const [dbStats, discordHealth, wsStats] = await Promise.all([
        databaseService.getStats(),
        discordService.healthCheck(),
        Promise.resolve(notificationService.getStats()),
      ]);

      res.json({
        database: dbStats,
        discord: {
          status: discordHealth ? 'healthy' : 'unhealthy',
        },
        websockets: wsStats,
        timestamp: new Date().toISOString(),
      });

    } catch (error) {
      logger.error('Error fetching admin stats:', error);

      res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'production' ? 'An error occurred' : 'Failed to fetch statistics',
      });
    }
  }
);

// Verification listing with rate limiting
router.get('/verifications', adminRateLimit, async (_req: Request, res: Response) => {
    try {
      logger.info('Fetching all verifications');

      const { prisma } = databaseService;

      const verifications = await prisma.adminVerification.findMany({
        include: {
          history: {
            orderBy: {
              timestamp: 'desc',
            },
            take: 5,
          },
        },
        orderBy: {
          lastVerified: 'desc',
        },
      });

      res.json({
        verifications,
        count: verifications.length,
      });

    } catch (error) {
      logger.error('Error fetching verifications:', error);

      res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'production' ? 'An error occurred' : 'Failed to fetch verifications',
      });
    }
  }
);

// User verification with strict rate limiting
router.post('/verify-user',
  adminRateLimit,
  validateAndSanitize(adminVerifyUserSchema),
  async (req: Request, res: Response) => {
    try {
      const { discordUserId, adminUserId } = req.body;

      if (!discordUserId) {
        return res.status(400).json({
          error: 'Missing required fields',
          message: 'discordUserId is required',
        });
      }

      logger.info(`Manual verification request for user ${discordUserId} by admin ${adminUserId}`);

      // CRITICAL FIX: Wrap in transaction to prevent race conditions
      const verification = await databaseService.prisma.$transaction(async (tx) => {
        // Update or create admin verification
        const verification = await tx.adminVerification.upsert({
          where: { discordUserId },
          update: {
            isActive: true,
            lastVerified: new Date(),
          },
          create: {
            discordUserId,
            uniqueIdentifier: `manual_verification_${Date.now()}_${discordUserId}`,
            passportFingerprint: `manual_${Date.now()}_${discordUserId}`,
            isActive: true,
          },
        });

        // Log the manual verification
        await tx.verificationHistory.create({
          data: {
            discordUserId,
            success: true,
          },
        });

        return verification;
      });

      // Update Discord roles
      const roleUpdateSuccess = await discordService.assignAdminRole(discordUserId);

      // Send success notification
      await notificationService.sendVerificationSuccess(discordUserId);

      res.json({
        success: true,
        verification,
        roleUpdateSuccess,
        message: 'User verified successfully',
      });

    } catch (error) {
      logger.error('Manual verification error:', error);

      res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'production' ? 'An error occurred' : 'Manual verification failed',
      });
    }
  }
);

// Revocation with strict rate limiting
router.post('/revoke-user',
  adminRateLimit,
  validateAndSanitize(adminRevokeUserSchema),
  async (req: Request, res: Response) => {
    try {
      const { discordUserId, adminUserId, reason } = req.body;

      if (!discordUserId) {
        return res.status(400).json({
          error: 'Missing required fields',
          message: 'discordUserId is required',
        });
      }

      logger.info(`Verification revocation request for user ${discordUserId} by admin ${adminUserId}`);

      // CRITICAL FIX: Wrap in transaction to prevent race conditions
      const verification = await databaseService.prisma.$transaction(async (tx) => {
        // Deactivate the verification
        const verification = await tx.adminVerification.update({
          where: { discordUserId },
          data: {
            isActive: false,
            lastVerified: new Date(),
          },
        });

        // Log the revocation
        await tx.verificationHistory.create({
          data: {
            discordUserId,
            success: false,
            errorMessage: `Verification revoked by admin ${adminUserId}${reason ? `: ${reason}` : ''}`,
          },
        });

        return verification;
      });

      // Remove Discord roles
      const roleUpdateSuccess = await discordService.removeAdminRole(discordUserId);

      res.json({
        success: true,
        verification,
        roleUpdateSuccess,
        message: 'User verification revoked successfully',
      });

    } catch (error) {
      logger.error('Verification revocation error:', error);

      res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'production' ? 'An error occurred' : 'Verification revocation failed',
      });
    }
  }
);

// Session monitoring with rate limiting
router.get('/sessions', adminRateLimit, async (_req: Request, res: Response) => {
    try {
      logger.info('Fetching active verification sessions');

      const { prisma } = databaseService;

      const sessions = await prisma.verificationSession.findMany({
        where: {
          expiresAt: {
            gt: new Date(),
          },
          used: false,
        },
        orderBy: {
          createdAt: 'desc',
        },
      });

      res.json({
        sessions,
        count: sessions.length,
      });

    } catch (error) {
      logger.error('Error fetching sessions:', error);

      res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'production' ? 'An error occurred' : 'Failed to fetch sessions',
      });
    }
  }
);

// Cleanup with very strict rate limiting
router.delete('/cleanup', adminRateLimit, async (_req: Request, res: Response) => {
    try {
      logger.info('Starting admin cleanup');

      const [expiredSessions, oldHistory] = await Promise.all([
        databaseService.cleanupExpiredSessions(),
        databaseService.cleanupOldHistory(),
      ]);

      res.json({
        success: true,
        cleanup: {
          expiredSessions,
          oldHistory,
        },
        message: 'Cleanup completed successfully',
      });

    } catch (error) {
      logger.error('Admin cleanup error:', error);

      res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'production' ? 'An error occurred' : 'Cleanup failed',
      });
    }
  }
);

export default router;