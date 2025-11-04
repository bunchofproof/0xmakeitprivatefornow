import { PrismaClient } from '@prisma/client';
import { VerificationSession, UserVerification, AdminVerification } from '@shared/types';
import { RateLimiter } from 'zk-discord-verifier-shared/dist/shared/src/utils/index';
import { logger } from '../logger';
import { sessionManager } from '../sessionManager';

// Database driver interface
interface IDatabaseDriver {
  initializeDatabase(): Promise<void>;
  createVerificationSession(sessionData: Partial<VerificationSession>): Promise<VerificationSession>;
  findVerificationSession(sessionId: string): Promise<any | null>;
  invalidateAndPersistSessionSync(tx: any, sessionId: string, session: any): Promise<void>;
  checkRateLimit(userId: string): Promise<{ allowed: boolean; resetTime?: number }>;
  getUserVerificationStatus(discordUserId: string): Promise<UserVerification | null>;
  getPendingVerifications(limit: number): Promise<AdminVerification[]>;
  getVerificationStats(): Promise<{
    totalUsers: number;
    verifiedUsers: number;
    pendingVerifications: number;
    verificationRate: number;
    todayVerifications: number;
    weekVerifications: number;
  }>;
  approveVerification(discordUserId: string, adminUserId: string, reason?: string): Promise<boolean>;
  rejectVerification(discordUserId: string, adminUserId: string, reason: string): Promise<boolean>;
  performSessionCleanup(): Promise<{
    sessionsCleaned: number;
    adminVerificationsDeactivated: number;
    historyCleaned: number;
    errors: string[];
  }>;
  getSessionHealthStats(): Promise<{
    totalSessions: number;
    expiredSessions: number;
    activeSessions: number;
    totalAdminVerifications: number;
    activeAdminVerifications: number;
    expiredAdminVerifications: number;
    totalHistoryRecords: number;
  }>;
  cleanupExpiredSessions(): Promise<number>;
  cleanupExpiredAdminVerifications(): Promise<number>;
  executeTransaction(resourceNames: string[], operations: (tx: any) => Promise<void>): Promise<void>;
  readFile(filename: string): Promise<any[]>;
  disconnect(): Promise<void>;
}

// Prisma Database Driver - connects to PostgreSQL via Prisma
export class PrismaDatabaseDriver implements IDatabaseDriver {
  private prisma: PrismaClient;
  private verificationRateLimiter: RateLimiter;

  constructor() {
    this.prisma = new PrismaClient({
      log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
    });
    this.verificationRateLimiter = new RateLimiter(3, 60000); // 3 attempts per minute
  }

  async initializeDatabase(): Promise<void> {
    try {
      await this.prisma.$connect();
      logger.info('Prisma database connection established');
    } catch (error) {
      logger.error('Failed to connect to Prisma database:', error instanceof Error ? error : new Error(String(error)));
      throw error;
    }
  }

  async createVerificationSession(sessionData: Partial<VerificationSession>): Promise<VerificationSession> {
    try {
      // Validate required fields - same validation as JSON driver
      if (!sessionData.id) {
        throw new Error('Session ID is required for verification session creation');
      }
      if (!sessionData.token) {
        throw new Error('Token is required for verification session creation');
      }
      if (!sessionData.discordUserId) {
        throw new Error('Discord user ID is required for verification session creation');
      }
      if (!sessionData.expiresAt) {
        throw new Error('ExpiresAt date is required for verification session creation');
      }

      // Create the verification session only
      const result = await this.prisma.$transaction(async (tx) => {
        const session = await tx.verificationSession.create({
          data: {
            id: sessionData.id!,  // Include the provided session ID
            token: sessionData.token!,
            discordUserId: sessionData.discordUserId!,
            expiresAt: sessionData.expiresAt!,
            bindingHash: "", // Add placeholder value for required field
            lastContextHash: "", // Add placeholder value for required field
          },
        });

        return session;
      });

      logger.debug(`Created verification session for user ${sessionData.discordUserId}`);
      return {
        id: result.id,
        token: result.token,
        discordUserId: result.discordUserId,
        status: 'pending' as const,
        createdAt: result.createdAt,
        expiresAt: result.expiresAt,
        attempts: 0,
        maxAttempts: 3,
      };
    } catch (error) {
      logger.error('Error creating verification session:', error instanceof Error ? error : new Error(String(error)));
      throw new Error('Failed to create verification session');
    }
  }

  async checkRateLimit(userId: string): Promise<{ allowed: boolean; resetTime?: number }> {
    const allowed = this.verificationRateLimiter.isAllowed(userId);
    const record = this.verificationRateLimiter['attempts'].get(userId);

    return {
      allowed,
      resetTime: record?.resetTime,
    };
  }

  async getUserVerificationStatus(discordUserId: string): Promise<UserVerification | null> {
    try {
      const verification = await this.prisma.adminVerification.findUnique({
        where: { discordUserId },
      });

      if (!verification) {
        return null;
      }

      // Map AdminVerification to UserVerification format for compatibility
      return {
        id: verification.id,
        discordUserId: verification.discordUserId,
        isVerified: verification.isActive,
        verifiedAt: verification.lastVerified,
        lastVerificationDate: verification.createdAt,
        expiresAt: verification.expiryDate,
        adminVerified: verification.isActive,
        adminVerifiedBy: verification.discordUserId, // Using the same user ID as verified by for now
        adminVerifiedAt: verification.lastVerified,
      } as UserVerification;
    } catch (error) {
      logger.error('Error fetching user verification status:', error instanceof Error ? error : new Error(String(error)));
      throw new Error('Failed to fetch verification status');
    }
  }

  async getPendingVerifications(limit: number = 10): Promise<AdminVerification[]> {
    try {
      const pending = await this.prisma.adminVerification.findMany({
        where: {
          isActive: false,
        },
        orderBy: {
          createdAt: 'desc',
        },
        take: limit,
      });

      return pending.map(p => ({
        id: p.id,
        discordUserId: p.discordUserId,
        adminUserId: p.discordUserId, // Using discordUserId as adminUserId for compatibility
        status: 'pending' as const,
        reason: undefined,
        createdAt: p.createdAt,
        reviewedAt: undefined,
        expiresAt: p.expiryDate || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      }));
    } catch (error) {
      logger.error('Error fetching pending verifications:', error instanceof Error ? error : new Error(String(error)));
      throw new Error('Failed to fetch pending verifications');
    }
  }

  async getVerificationStats(): Promise<{
    totalUsers: number;
    verifiedUsers: number;
    pendingVerifications: number;
    verificationRate: number;
    todayVerifications: number;
    weekVerifications: number;
  }> {
    try {
      const totalUsers = await this.prisma.adminVerification.count();
      const verifiedUsers = await this.prisma.adminVerification.count({
        where: { isActive: true },
      });

      const pendingVerifications = await this.prisma.adminVerification.count({
        where: { isActive: false },
      });

      const today = new Date();
      today.setHours(0, 0, 0, 0);

      const weekAgo = new Date(today);
      weekAgo.setDate(weekAgo.getDate() - 7);

      const todayVerifications = await this.prisma.verificationHistory.count({
        where: {
          success: true,
          timestamp: {
            gte: today,
          },
        },
      });

      const weekVerifications = await this.prisma.verificationHistory.count({
        where: {
          success: true,
          timestamp: {
            gte: weekAgo,
          },
        },
      });

      const verificationRate = totalUsers > 0 ? Math.round((verifiedUsers / totalUsers) * 100) : 0;

      return {
        totalUsers,
        verifiedUsers,
        pendingVerifications,
        verificationRate,
        todayVerifications,
        weekVerifications,
      };
    } catch (error) {
      logger.error('Error fetching verification stats:', error instanceof Error ? error : new Error(String(error)));
      throw new Error('Failed to fetch verification statistics');
    }
  }

  async approveVerification(discordUserId: string, adminUserId: string): Promise<boolean> {
    try {
      // Start a transaction to ensure data consistency
      await this.prisma.$transaction(async (tx) => {
        // Update or create admin verification record
        await tx.adminVerification.upsert({
          where: { discordUserId },
          update: {
            isActive: true,
            lastVerified: new Date(),
          },
          create: {
            discordUserId,
            passportFingerprint: `approved_fingerprint_${discordUserId}_${Date.now()}`, // Generate fingerprint for approved user
            uniqueIdentifier: `approved_${discordUserId}_${Date.now()}`, // Generate unique identifier for approved user
            isActive: true,
            lastVerified: new Date(),
            expiryDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
          },
        });

        // Log the action
        await tx.verificationHistory.create({
          data: {
            discordUserId,
            success: true,
            timestamp: new Date(),
            errorMessage: null,
          },
        });
      });

      logger.info(`Verification approved for user ${discordUserId} by admin ${adminUserId}`);
      return true;
    } catch (error) {
      logger.error('Error approving verification:', error instanceof Error ? error : new Error(String(error)));
      return false;
    }
  }

  async rejectVerification(discordUserId: string, adminUserId: string, reason: string): Promise<boolean> {
    try {
      await this.prisma.$transaction(async (tx) => {
        // Update admin verification record
        await tx.adminVerification.upsert({
          where: { discordUserId },
          update: {
            isActive: false,
          },
          create: {
            discordUserId,
            passportFingerprint: `rejected_fingerprint_${discordUserId}_${Date.now()}`, // Generate fingerprint for rejected user
            uniqueIdentifier: `rejected_${discordUserId}_${Date.now()}`, // Generate unique identifier for rejected user
            isActive: false,
            expiryDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
          },
        });

        // Log the action
        await tx.verificationHistory.create({
          data: {
            discordUserId,
            success: false,
            timestamp: new Date(),
            errorMessage: reason,
          },
        });
      });

      logger.info(`Verification rejected for user ${discordUserId} by admin ${adminUserId}. Reason: ${reason}`);
      return true;
    } catch (error) {
      logger.error('Error rejecting verification:', error instanceof Error ? error : new Error(String(error)));
      return false;
    }
  }

  async findVerificationSession(sessionId: string): Promise<any | null> {
    try {
      const session = await this.prisma.verificationSession.findUnique({
        where: { id: sessionId },
      });

      if (!session) return null;

      return {
        id: session.id,
        discordUserId: session.discordUserId,
        token: session.token,
        status: 'pending',
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
        used: session.used,
        attempts: 0,
        maxAttempts: 3,
      };
    } catch (error) {
      logger.error('Error finding verification session:', error instanceof Error ? error : new Error(String(error)));
      return null;
    }
  }

  async invalidateAndPersistSessionSync(tx: any, sessionId: string): Promise<void> {
    await tx.verificationSession.update({
      where: { id: sessionId },
      data: {
        used: true,
        lastUsedAt: new Date(),
      },
    });
  }

  async executeTransaction(_resourceNames: string[], operations: (tx: any) => Promise<void>): Promise<void> {
    await this.prisma.$transaction(async (tx: any) => {
      return await operations(tx);
    });
  }

  async readFile(): Promise<any[]> {
    throw new Error('readFile not implemented for Prisma driver');
  }

  async performSessionCleanup(): Promise<{
    sessionsCleaned: number;
    adminVerificationsDeactivated: number;
    historyCleaned: number;
    errors: string[];
  }> {
    try {
      return await sessionManager.performFullMaintenance();
    } catch (error) {
      logger.error('Failed to perform session cleanup:', error instanceof Error ? error : new Error(String(error)));
      return {
        sessionsCleaned: 0,
        adminVerificationsDeactivated: 0,
        historyCleaned: 0,
        errors: [`Cleanup failed: ${error instanceof Error ? error.message : String(error)}`],
      };
    }
  }

  async getSessionHealthStats(): Promise<{
    totalSessions: number;
    expiredSessions: number;
    activeSessions: number;
    totalAdminVerifications: number;
    activeAdminVerifications: number;
    expiredAdminVerifications: number;
    totalHistoryRecords: number;
  }> {
    try {
      return await sessionManager.getSessionHealthStats();
    } catch (error) {
      logger.error('Failed to get session health stats:', error instanceof Error ? error : new Error(String(error)));
      throw new Error('Failed to retrieve session health statistics');
    }
  }

  async cleanupExpiredSessions(): Promise<number> {
    try {
      const result = await sessionManager.cleanupExpiredSessions();
      if (result.errors.length > 0) {
        logger.warn('Session cleanup errors:', result.errors);
      }
      return result.deletedCount;
    } catch (error) {
      logger.error('Failed to cleanup expired sessions:', error instanceof Error ? error : new Error(String(error)));
      return 0;
    }
  }

  async cleanupExpiredAdminVerifications(): Promise<number> {
    try {
      const result = await sessionManager.cleanupExpiredAdminVerifications();
      if (result.errors.length > 0) {
        logger.warn('Admin verification cleanup errors:', result.errors);
      }
      return result.deactivatedCount;
    } catch (error) {
      logger.error('Failed to cleanup expired admin verifications:', error instanceof Error ? error : new Error(String(error)));
      return 0;
    }
  }
  async disconnect(): Promise<void> {
    try {
      await this.prisma.$disconnect();
      logger.info('Prisma database connection closed');
    } catch (error) {
      logger.error('Error disconnecting Prisma database:', error instanceof Error ? error : new Error(String(error)));
    }
  }
}