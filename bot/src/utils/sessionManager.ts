import { PrismaClient } from '@prisma/client';
import { logger } from './logger';

const prisma = new PrismaClient();

/**
 * Session cleanup configuration
 */
export interface CleanupConfig {
  sessionRetentionHours: number;
  adminVerificationRetentionHours: number;
  batchSize: number;
  dryRun: boolean;
}

/**
 * Default cleanup configuration
 */
export const defaultCleanupConfig: CleanupConfig = {
  sessionRetentionHours: 24, // Clean sessions after 24 hours
  adminVerificationRetentionHours: 30 * 24, // Clean expired admin verifications after 30 days past expiry
  batchSize: 1000,
  dryRun: false,
};

/**
 * Session management utilities for production cleanup
 */
export class SessionManager {
  private config: CleanupConfig;

  constructor(config: Partial<CleanupConfig> = {}) {
    this.config = { ...defaultCleanupConfig, ...config };
  }

  /**
   * Clean up expired verification sessions
   */
  async cleanupExpiredSessions(): Promise<{
    deletedCount: number;
    errors: string[];
  }> {
    const errors: string[] = [];
    let deletedCount = 0;

    try {
      const cutoffDate = new Date(Date.now() - (this.config.sessionRetentionHours * 60 * 60 * 1000));

      if (this.config.dryRun) {
        const count = await prisma.verificationSession.count({
          where: {
            expiresAt: { lt: cutoffDate },
          },
        });
        logger.info(`[DRY RUN] Would delete ${count} expired verification sessions`);
        return { deletedCount: count, errors };
      }

      // Delete in batches to avoid lock timeouts
      while (true) {
        const batch = await prisma.verificationSession.findMany({
          where: {
            expiresAt: { lt: cutoffDate },
          },
          take: this.config.batchSize,
          select: { id: true },
        });

        if (batch.length === 0) break;

        const ids = batch.map(s => s.id);
        const result = await prisma.verificationSession.deleteMany({
          where: { id: { in: ids } },
        });

        deletedCount += result.count;

        if (batch.length < this.config.batchSize) break;
      }

      logger.info(`Cleaned up ${deletedCount} expired verification sessions`);
    } catch (error) {
      const errorMsg = `Failed to cleanup expired sessions: ${error}`;
      logger.error(errorMsg);
      errors.push(errorMsg);
    }

    return { deletedCount, errors };
  }

  /**
   * Clean up expired admin verifications (those past their expiry date)
   */
  async cleanupExpiredAdminVerifications(): Promise<{
    deactivatedCount: number;
    errors: string[];
  }> {
    const errors: string[] = [];
    let deactivatedCount = 0;

    try {
      const cutoffDate = new Date(Date.now() - (this.config.adminVerificationRetentionHours * 60 * 60 * 1000));

      if (this.config.dryRun) {
        const count = await prisma.adminVerification.count({
          where: {
            isActive: true,
            expiryDate: { lt: cutoffDate },
          },
        });
        logger.info(`[DRY RUN] Would deactivate ${count} expired admin verifications`);
        return { deactivatedCount: count, errors };
      }

      // Deactivate in batches
      while (true) {
        const batch = await prisma.adminVerification.findMany({
          where: {
            isActive: true,
            expiryDate: { lt: cutoffDate },
          },
          take: this.config.batchSize,
          select: { id: true, discordUserId: true },
        });

        if (batch.length === 0) break;

        const ids = batch.map(v => v.id);
        const result = await prisma.adminVerification.updateMany({
          where: { id: { in: ids } },
          data: { isActive: false },
        });

        deactivatedCount += result.count;

        // Log deactivation history for each
        for (const verification of batch) {
          await prisma.verificationHistory.create({
            data: {
              discordUserId: verification.discordUserId,
              success: false,
              errorMessage: 'Auto-deactivated due to expiry',
              timestamp: new Date(),
            },
          });
        }

        if (batch.length < this.config.batchSize) break;
      }

      logger.info(`Deactivated ${deactivatedCount} expired admin verifications`);
    } catch (error) {
      const errorMsg = `Failed to cleanup expired admin verifications: ${error}`;
      logger.error(errorMsg);
      errors.push(errorMsg);
    }

    return { deactivatedCount, errors };
  }

  /**
   * Clean up old verification history records (older than retention period)
   */
  async cleanupOldVerificationHistory(retentionDays: number = 90): Promise<{
    deletedCount: number;
    errors: string[];
  }> {
    const errors: string[] = [];
    let deletedCount = 0;

    try {
      const cutoffDate = new Date(Date.now() - (retentionDays * 24 * 60 * 60 * 1000));

      if (this.config.dryRun) {
        const count = await prisma.verificationHistory.count({
          where: {
            timestamp: { lt: cutoffDate },
          },
        });
        logger.info(`[DRY RUN] Would delete ${count} old verification history records`);
        return { deletedCount: count, errors };
      }

      // Delete in batches
      while (true) {
        const batch = await prisma.verificationHistory.findMany({
          where: {
            timestamp: { lt: cutoffDate },
          },
          take: this.config.batchSize,
          select: { id: true },
        });

        if (batch.length === 0) break;

        const ids = batch.map(h => h.id);
        const result = await prisma.verificationHistory.deleteMany({
          where: { id: { in: ids } },
        });

        deletedCount += result.count;

        if (batch.length < this.config.batchSize) break;
      }

      logger.info(`Cleaned up ${deletedCount} old verification history records`);
    } catch (error) {
      const errorMsg = `Failed to cleanup old verification history: ${error}`;
      logger.error(errorMsg);
      errors.push(errorMsg);
    }

    return { deletedCount, errors };
  }

  /**
   * Get session health statistics
   */
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
      const [
        totalSessions,
        expiredSessions,
        activeSessions,
        totalAdminVerifications,
        activeAdminVerifications,
        expiredAdminVerifications,
        totalHistoryRecords,
      ] = await Promise.all([
        prisma.verificationSession.count(),
        prisma.verificationSession.count({
          where: { expiresAt: { lt: new Date() } },
        }),
        prisma.verificationSession.count({
          where: { expiresAt: { gte: new Date() } },
        }),
        prisma.adminVerification.count(),
        prisma.adminVerification.count({
          where: { isActive: true },
        }),
        prisma.adminVerification.count({
          where: { isActive: true, expiryDate: { lt: new Date() } },
        }),
        prisma.verificationHistory.count(),
      ]);

      return {
        totalSessions,
        expiredSessions,
        activeSessions,
        totalAdminVerifications,
        activeAdminVerifications,
        expiredAdminVerifications,
        totalHistoryRecords,
      };
    } catch (error) {
      logger.error('Failed to get session health stats:', error instanceof Error ? error : new Error(String(error)));
      throw error instanceof Error ? error : new Error(String(error));
    }
  }

  /**
   * Perform full maintenance cleanup
   */
  async performFullMaintenance(): Promise<{
    sessionsCleaned: number;
    adminVerificationsDeactivated: number;
    historyCleaned: number;
    errors: string[];
  }> {
    logger.info('Starting full maintenance cleanup...');

    const results = await Promise.allSettled([
      this.cleanupExpiredSessions(),
      this.cleanupExpiredAdminVerifications(),
      this.cleanupOldVerificationHistory(),
    ]);

    const errors: string[] = [];
    let sessionsCleaned = 0;
    let adminVerificationsDeactivated = 0;
    let historyCleaned = 0;

    results.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        const data = result.value;
        errors.push(...data.errors);
        if (index === 0) sessionsCleaned = (data as { deletedCount: number; errors: string[] }).deletedCount || 0;
        else if (index === 1) adminVerificationsDeactivated = (data as { deactivatedCount: number; errors: string[] }).deactivatedCount || 0;
        else if (index === 2) historyCleaned = (data as { deletedCount: number; errors: string[] }).deletedCount || 0;
      } else {
        errors.push(`Cleanup ${index} failed: ${result.reason}`);
      }
    });

    logger.info(`Full maintenance complete. Sessions: ${sessionsCleaned}, Admin Verifications: ${adminVerificationsDeactivated}, History: ${historyCleaned}`);

    return {
      sessionsCleaned,
      adminVerificationsDeactivated,
      historyCleaned,
      errors,
    };
  }
}

// Export singleton instance
export const sessionManager = new SessionManager();