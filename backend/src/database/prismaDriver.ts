import { PrismaClient } from '@prisma/client';
import {
  DatabaseOperations,
  VerificationSession,
  AdminVerification,
  VerificationHistory
} from './interfaces';
import { logger } from '../utils/logger';

export class PrismaDatabaseDriver implements DatabaseOperations {
  private prisma: PrismaClient;

  constructor() {
    this.prisma = new PrismaClient({
      log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
    });
  }

  async healthCheck(): Promise<boolean> {
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      return true;
    } catch (error) {
      logger.error('Prisma health check failed:', error);
      return false;
    }
  }

  async findVerificationSession(id: string): Promise<VerificationSession | null> {
    try {
      const session = await this.prisma.verificationSession.findUnique({
        where: { id },
      });

      if (!session) return null;

      return {
        id: session.id,
        discordUserId: session.discordUserId,
        token: session.token,
        expiresAt: session.expiresAt,
        createdAt: session.createdAt,
        used: session.used,
        attempts: 0, // Not in Prisma schema, default to 0
        maxAttempts: 3, // Not in Prisma schema, default to 3
        status: 'pending', // Not in Prisma schema, default to pending
        bindingHash: session.bindingHash,
        lastContextHash: session.lastContextHash
      };
    } catch (error) {
      logger.error('Error finding verification session:', error);
      throw new Error('Failed to find verification session');
    }
  }

  async createVerificationSession(session: Omit<VerificationSession, 'createdAt'>): Promise<VerificationSession> {
    try {
      const created = await this.prisma.verificationSession.create({
        data: {
          id: session.id,
          token: session.token,
          discordUserId: session.discordUserId,
          expiresAt: session.expiresAt,
          used: session.used,
          bindingHash: session.bindingHash || "",
          lastContextHash: session.lastContextHash || "",
        },
      });

      return {
        id: created.id,
        discordUserId: created.discordUserId,
        token: created.token,
        expiresAt: created.expiresAt,
        createdAt: new Date(),
        used: created.used,
        attempts: session.attempts || 0,
        maxAttempts: session.maxAttempts || 3,
        status: session.status || 'pending',
        bindingHash: created.bindingHash || '',
        lastContextHash: created.lastContextHash || ''
      };
    } catch (error) {
      logger.error('Error creating verification session:', error);
      throw new Error('Failed to create verification session');
    }
  }

  async updateVerificationSession(id: string, updates: Partial<VerificationSession>): Promise<VerificationSession | null> {
    try {
      const updated = await this.prisma.verificationSession.update({
        where: { id },
        data: {
          ...(updates.used !== undefined && { used: updates.used }),
          ...(updates.expiresAt && { expiresAt: updates.expiresAt }),
        },
      });

      return {
        id: updated.id,
        discordUserId: updated.discordUserId,
        token: updated.token,
        expiresAt: updated.expiresAt,
        createdAt: updated.createdAt,
        used: updated.used,
        attempts: 0, // Default
        maxAttempts: 3, // Default
        status: 'pending', // Default
        bindingHash: updated.bindingHash || '',
        lastContextHash: updated.lastContextHash || ''
      };
    } catch (error) {
      logger.error('Error updating verification session:', error);
      throw new Error('Failed to update verification session');
    }
  }

  async markSessionAsUsed(id: string): Promise<boolean> {
    try {
      const result = await this.updateVerificationSession(id, { used: true });
      return result !== null;
    } catch (error) {
      logger.error('Error marking session as used:', error);
      return false;
    }
  }

  async findAdminVerification(discordUserId: string): Promise<AdminVerification | null> {
    try {
      const verification = await this.prisma.adminVerification.findUnique({
        where: { discordUserId },
      });

      if (!verification) return null;

      return {
        id: verification.id,
        discordUserId: verification.discordUserId,
        passportFingerprint: verification.passportFingerprint,
        uniqueIdentifier: verification.uniqueIdentifier,
        isActive: verification.isActive,
        lastVerified: verification.lastVerified,
        createdAt: verification.createdAt,
      };
    } catch (error) {
      logger.error('Error finding admin verification:', error);
      throw new Error('Failed to find admin verification');
    }
  }

  async findVerificationByUniqueIdentifier(uniqueIdentifier: string): Promise<AdminVerification | null> {
    try {
      const verification = await this.prisma.adminVerification.findUnique({
        where: { uniqueIdentifier },
      });

      if (!verification) return null;

      return {
        id: verification.id,
        discordUserId: verification.discordUserId,
        passportFingerprint: verification.passportFingerprint,
        uniqueIdentifier: verification.uniqueIdentifier,
        isActive: verification.isActive,
        lastVerified: verification.lastVerified,
        createdAt: verification.createdAt,
      };
    } catch (error) {
      logger.error('Error finding verification by unique identifier:', error);
      throw new Error('Failed to find verification by unique identifier');
    }
  }

  async findVerificationByFingerprint(passportFingerprint: string): Promise<AdminVerification | null> {
    try {
      const verification = await this.prisma.adminVerification.findFirst({
        where: { passportFingerprint },
      });

      if (!verification) return null;

      return {
        id: verification.id,
        discordUserId: verification.discordUserId,
        passportFingerprint: verification.passportFingerprint,
        uniqueIdentifier: verification.uniqueIdentifier,
        isActive: verification.isActive,
        lastVerified: verification.lastVerified,
        createdAt: verification.createdAt,
      };
    } catch (error) {
      logger.error('Error finding verification by fingerprint:', error);
      throw new Error('Failed to find verification by fingerprint');
    }
  }

  async upsertAdminVerification(verification: Omit<AdminVerification, 'createdAt'>): Promise<AdminVerification> {
    try {
      const upserted = await this.prisma.adminVerification.upsert({
        where: { discordUserId: verification.discordUserId },
        update: {
          passportFingerprint: verification.passportFingerprint,
          uniqueIdentifier: verification.uniqueIdentifier,
          isActive: verification.isActive,
          lastVerified: verification.lastVerified,
          expiryDate: verification.expiryDate,
        },
        create: {
          discordUserId: verification.discordUserId,
          passportFingerprint: verification.passportFingerprint,
          uniqueIdentifier: verification.uniqueIdentifier,
          isActive: verification.isActive,
          lastVerified: verification.lastVerified,
          expiryDate: verification.expiryDate,
        },
      });

      return {
        id: upserted.id,
        discordUserId: upserted.discordUserId,
        passportFingerprint: upserted.passportFingerprint,
        uniqueIdentifier: upserted.uniqueIdentifier,
        isActive: upserted.isActive,
        lastVerified: upserted.lastVerified,
        createdAt: upserted.createdAt,
      };
    } catch (error) {
      logger.error('Error upserting admin verification:', error);
      throw new Error('Failed to upsert admin verification');
    }
  }

  async createVerificationHistory(history: Omit<VerificationHistory, 'id' | 'createdAt'>): Promise<VerificationHistory> {
    try {
      const created = await this.prisma.verificationHistory.create({
        data: {
          discordUserId: history.discordUserId || null, // Allow null for failed verifications before user identification
          success: history.success,
          errorMessage: history.errorMessage,
          timestamp: new Date(),
        },
      });

      return {
        id: created.id,
        discordUserId: created.discordUserId || '', // Return empty string if null for interface compatibility
        success: created.success,
        errorMessage: created.errorMessage || null,
        timestamp: created.timestamp,
        createdAt: new Date(),
      };
    } catch (error) {
      logger.error('Error creating verification history:', error);
      throw new Error('Failed to create verification history');
    }
  }

  async executeTransaction<T = any>(
    resourceNames: string[],
    transactionFn: (tx: any) => Promise<T>
  ): Promise<T> {
    return await this.prisma.$transaction(async (tx) => {
      return await transactionFn(tx);
    });
  }
}