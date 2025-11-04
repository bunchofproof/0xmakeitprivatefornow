import { VerificationSession, UserVerification, AdminVerification } from '@shared/types';
import { logger } from './logger';
import { PrismaDatabaseDriver } from './databaseDrivers';
import { config } from '../config';

// Create the appropriate database driver based on configuration
const databaseDriver = config.database.provider === 'postgresql'
  ? new PrismaDatabaseDriver()
  : null;

export async function initializeDatabase(): Promise<void> {
  try {
    if (!databaseDriver) {
      throw new Error(`Database driver not available for provider: ${config.database.provider}`);
    }
    await databaseDriver.initializeDatabase();
  } catch (error) {
    logger.error('Failed to initialize database:', error instanceof Error ? error : new Error(String(error)));
    throw error;
  }
}

export async function createVerificationSession(
  sessionData: Partial<VerificationSession>
): Promise<VerificationSession> {
  if (!databaseDriver) {
    throw new Error(`Database driver not available for provider: ${config.database.provider}`);
  }
  return await databaseDriver.createVerificationSession(sessionData);
}

export async function checkRateLimit(userId: string): Promise<{ allowed: boolean; resetTime?: number }> {
  if (!databaseDriver) {
    throw new Error(`Database driver not available for provider: ${config.database.provider}`);
  }
  return await databaseDriver.checkRateLimit(userId);
}

export async function getUserVerificationStatus(discordUserId: string): Promise<UserVerification | null> {
  if (!databaseDriver) {
    throw new Error(`Database driver not available for provider: ${config.database.provider}`);
  }
  return await databaseDriver.getUserVerificationStatus(discordUserId);
}

export async function getPendingVerifications(limit: number = 10): Promise<AdminVerification[]> {
  if (!databaseDriver) {
    throw new Error(`Database driver not available for provider: ${config.database.provider}`);
  }
  return await databaseDriver.getPendingVerifications(limit);
}

export async function getVerificationStats(): Promise<{
  totalUsers: number;
  verifiedUsers: number;
  pendingVerifications: number;
  verificationRate: number;
  todayVerifications: number;
  weekVerifications: number;
}> {
  if (!databaseDriver) {
    throw new Error(`Database driver not available for provider: ${config.database.provider}`);
  }
  return await databaseDriver.getVerificationStats();
}

export async function approveVerification(
  discordUserId: string,
  adminUserId: string
): Promise<boolean> {
  if (!databaseDriver) {
    throw new Error(`Database driver not available for provider: ${config.database.provider}`);
  }
  return await databaseDriver.approveVerification(discordUserId, adminUserId);
}

export async function rejectVerification(
  discordUserId: string,
  adminUserId: string,
  reason: string
): Promise<boolean> {
  if (!databaseDriver) {
    throw new Error(`Database driver not available for provider: ${config.database.provider}`);
  }
  return await databaseDriver.rejectVerification(discordUserId, adminUserId, reason);
}

// Session cleanup utilities
export async function performSessionCleanup(): Promise<{
  sessionsCleaned: number;
  adminVerificationsDeactivated: number;
  historyCleaned: number;
  errors: string[];
}> {
  if (!databaseDriver) {
    throw new Error(`Database driver not available for provider: ${config.database.provider}`);
  }
  return await databaseDriver.performSessionCleanup();
}

export async function getSessionHealthStats(): Promise<{
  totalSessions: number;
  expiredSessions: number;
  activeSessions: number;
  totalAdminVerifications: number;
  activeAdminVerifications: number;
  expiredAdminVerifications: number;
  totalHistoryRecords: number;
}> {
  if (!databaseDriver) {
    throw new Error(`Database driver not available for provider: ${config.database.provider}`);
  }
  return await databaseDriver.getSessionHealthStats();
}

export async function cleanupExpiredSessions(): Promise<number> {
  if (!databaseDriver) {
    throw new Error(`Database driver not available for provider: ${config.database.provider}`);
  }
  return await databaseDriver.cleanupExpiredSessions();
}

export async function cleanupExpiredAdminVerifications(): Promise<number> {
  if (!databaseDriver) {
    throw new Error(`Database driver not available for provider: ${config.database.provider}`);
  }
  return await databaseDriver.cleanupExpiredAdminVerifications();
}

export async function disconnectDatabase(): Promise<void> {
  if (!databaseDriver) {
    console.warn('Database driver not available for disconnect');
    return;
  }
  await databaseDriver.disconnect();
}