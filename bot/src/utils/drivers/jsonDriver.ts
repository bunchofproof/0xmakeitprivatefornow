import * as path from 'path';
import * as fs from 'fs';
import { randomBytes } from 'crypto';
import { VerificationSession, UserVerification, AdminVerification } from '@shared/types';
import { RateLimiter } from '@shared/utils';
import { logger } from '../logger';
import { sessionManager } from '../sessionManager';

// Import the shared concurrency control system
import { DatabaseLockManager } from 'zk-discord-verifier-shared/dist/shared/src/utils/databaseLockManager';
// Removed invalid imports - these functions don't exist in databaseDrivers.ts

// Updated AdminVerification interface to match Prisma schema
interface AdminVerificationWithFingerprint {
  id: string;
  discordUserId: string;
  uniqueIdentifier: string;
  passportFingerprint: string;
  isActive: boolean;
  lastVerified: Date;
  createdAt: Date;
  expiryDate?: Date;
}

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

// JSON Database Driver with concurrency control
export class JsonDatabaseDriver implements IDatabaseDriver {
  private verificationRateLimiter: RateLimiter;
  private databaseDir: string;
  private lockManager: DatabaseLockManager;

  constructor(databasePath?: string) {
    // Initialize rate limiter with correct configuration from config
    // This will be properly initialized in the checkRateLimit method
    this.verificationRateLimiter = new RateLimiter(3, 60000); // Temporary, will be replaced

    // Securely validate and set the database directory
    try {
      // Use default database directory if none provided, or validate the provided path
      this.databaseDir = databasePath || path.join(process.cwd(), 'database');
      // Basic validation - ensure it's a string and not empty
      if (!this.databaseDir || typeof this.databaseDir !== 'string') {
        throw new Error('Invalid database path provided');
      }
      logger.info(`Database directory set to: ${this.databaseDir}`);

      // Initialize the shared lock manager
      this.lockManager = new DatabaseLockManager(this.databaseDir);

    } catch (error) {
      logger.error('Database path validation failed:', error instanceof Error ? error : new Error(String(error)));
      throw new Error(`Failed to initialize database: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async initializeDatabase(): Promise<void> {
    try {
      // Ensure database directory exists
      if (!fs.existsSync(this.databaseDir)) {
        fs.mkdirSync(this.databaseDir, { recursive: true });
      }

      // Create files if they don't exist
      const files = [
        'verification-sessions.json',
        'admin-verifications.json',
        'verification-history.json'
      ];

      for (const file of files) {
        const filePath = path.join(this.databaseDir, file);
        if (!fs.existsSync(filePath)) {
          fs.writeFileSync(filePath, JSON.stringify([], null, 2));
        }
      }

      // Database initialization completed
      // Database initialization completed with lock manager
      // Note: Database validation is handled by the lock manager

      logger.info('JSON database initialized with concurrency control');
    } catch (error) {
      logger.error('Failed to initialize JSON database:', error instanceof Error ? error : new Error(String(error)));
      throw error;
    }
  }

  async createVerificationSession(sessionData: Partial<VerificationSession>): Promise<VerificationSession> {
    try {
      // Validate required fields with detailed logging
      if (!sessionData.token) {
        throw new Error('Token is required for verification session creation');
      }
      if (!sessionData.discordUserId) {
        throw new Error('Discord user ID is required for verification session creation');
      }
      if (!sessionData.expiresAt) {
        throw new Error('ExpiresAt date is required for verification session creation');
      }

      // Use the provided session ID - this is the critical fix for the missing ingredient
      const sessionId = sessionData.id;

      // Validate session ID is provided and format is correct
      if (!sessionId) {
        throw new Error('Session ID is required for verification session creation');
      }

      if (typeof sessionId !== 'string' || sessionId.length < 16) {
        throw new Error(`Invalid session ID format: ${typeof sessionId}, length: ${sessionId?.length || 0}`);
      }

      // Validate token format
      if (typeof sessionData.token !== 'string' || sessionData.token.length < 16) {
        throw new Error(`Invalid token format: ${typeof sessionData.token}, length: ${sessionData.token?.length || 0}`);
      }

      const newSession: VerificationSession = {
        id: sessionId,           // Use the provided session ID
        token: sessionData.token!,
        discordUserId: sessionData.discordUserId!,
        status: 'pending' as const,
        createdAt: new Date(),
        expiresAt: sessionData.expiresAt!,
        attempts: 0, // Always start with 0 attempts for new sessions
        maxAttempts: 3, // Use fixed max attempts for consistency
      };

      logger.debug(`JSON DB: Creating session with data:`, {
        sessionId: newSession.id,
        tokenLength: newSession.token.length,
        discordUserId: newSession.discordUserId,
        expiresAt: newSession.expiresAt,
        maxAttempts: newSession.maxAttempts,
      });

      // Use transaction to ensure atomic session creation with AdminVerification upsert
      await this.lockManager.executeTransaction(['verification-sessions.json', 'admin-verifications.json'], async (tx) => {
        // First upsert AdminVerification record to prevent foreign key constraint
        const adminVerifications = await tx.read('admin-verifications.json');
        if (!Array.isArray(adminVerifications)) {
          throw new Error(`Invalid admin verifications data type: ${typeof adminVerifications}`);
        }

        const existingIndex = adminVerifications.findIndex((v: AdminVerificationWithFingerprint) => v.discordUserId === sessionData.discordUserId);

        if (existingIndex >= 0) {
          // Update existing record if needed
          adminVerifications[existingIndex] = {
            ...adminVerifications[existingIndex],
            lastVerified: new Date(),
          };
        } else {
          // Create new AdminVerification record
          const newAdminVerification: AdminVerificationWithFingerprint = {
            id: randomBytes(32).toString('hex'),
            discordUserId: sessionData.discordUserId!,
            uniqueIdentifier: `pending_${sessionData.discordUserId}_${Date.now()}`,
            passportFingerprint: `pending_fingerprint_${sessionData.discordUserId}_${Date.now()}`,
            isActive: false,
            lastVerified: new Date(),
            createdAt: new Date(),
          };
          adminVerifications.push(newAdminVerification);
        }

        await tx.write('admin-verifications.json', adminVerifications);

        // Now create the verification session
        const sessions = await tx.read('verification-sessions.json');

        // Validate existing sessions array
        if (!Array.isArray(sessions)) {
          throw new Error(`Invalid sessions data type: ${typeof sessions}`);
        }

        sessions.push(newSession);
        await tx.write('verification-sessions.json', sessions);

        logger.info(`JSON DB: Successfully persisted session ${sessionId} to database`);
      });

      logger.debug(`JSON DB: Created verification session for user ${sessionData.discordUserId}`);
      return newSession;

    } catch (error) {
      // COMPREHENSIVE ERROR CAPTURE - This captures the mystery empty error
      const errorType = error instanceof Error ? error.constructor.name : typeof error;
      const errorMessage = error instanceof Error ? error.message : String(error);
      const errorStack = error instanceof Error ? error.stack : undefined;

      // CRITICAL: Log detailed error information for debugging empty messages
      console.error('\n🚨 DATABASE TRANSACTION ERROR CAPTURED 🚨');
      console.error('Timestamp:', new Date().toISOString());
      console.error('Error Type:', errorType);
      console.error('Error Message:', `"${errorMessage}"`);
      console.error('Error Message Length:', errorMessage.length);
      console.error('Error Stack:', errorStack);
      console.error('Session Data:', JSON.stringify(sessionData, null, 2));
      console.error('Logger Status:', logger ? 'Available' : 'Undefined');
      console.error('LockManager Status:', this.lockManager ? 'Available' : 'Undefined');

      // Also log to logger if available
      try {
        if (logger) {
          logger.error(`JSON DB: CRITICAL ERROR - Type: ${errorType}, Message: "${errorMessage}", Length: ${errorMessage.length}`);
        }
      } catch (loggerError) {
        console.error('Failed to log to logger:', loggerError);
      }

      throw new Error(`Failed to create verification session: ${errorMessage}`);
    }
  }

  async checkRateLimit(userId: string): Promise<{ allowed: boolean; resetTime?: number }> {
    // Import config dynamically to avoid circular dependencies
    const config = await import('../../config').then(m => m.config).catch(() => ({
      rateLimit: { command: { points: 3, duration: 10 } }
    }));

    // Initialize rate limiter with correct configuration if not already done
    if (this.verificationRateLimiter['maxAttempts'] !== config.rateLimit.command.points ||
        this.verificationRateLimiter['windowMs'] !== config.rateLimit.command.duration * 60 * 1000) {
      this.verificationRateLimiter = new RateLimiter(
        config.rateLimit.command.points,
        config.rateLimit.command.duration * 60 * 1000
      );
    }

    const allowed = this.verificationRateLimiter.isAllowed(userId);
    const record = this.verificationRateLimiter['attempts'].get(userId);

    return {
      allowed,
      resetTime: record?.resetTime,
    };
  }

  async getUserVerificationStatus(discordUserId: string): Promise<UserVerification | null> {
    const verifications = await this.lockManager.atomicRead('admin-verifications.json');

    const verification = verifications.find((v: AdminVerificationWithFingerprint) => v.discordUserId === discordUserId);
    if (!verification) {
      return null;
    }

    return {
      id: verification.id,
      discordUserId: verification.discordUserId,
      isVerified: verification.isActive !== undefined ? verification.isActive : false,
      verifiedAt: verification.lastVerified,
      lastVerificationDate: verification.createdAt,
      expiresAt: verification.expiryDate,
      adminVerified: verification.isActive !== undefined ? verification.isActive : false,
      adminVerifiedBy: verification.discordUserId,
      adminVerifiedAt: verification.lastVerified,
    } as UserVerification;
  }

  async getPendingVerifications(limit: number = 10): Promise<AdminVerification[]> {
    const verifications = await this.lockManager.atomicRead('admin-verifications.json');

    const pending = verifications
      .filter((v: AdminVerificationWithFingerprint) => v.isActive === undefined || !v.isActive)
      .sort((a: AdminVerificationWithFingerprint, b: AdminVerificationWithFingerprint) =>
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
      .slice(0, limit);

    return pending.map((p: AdminVerificationWithFingerprint) => ({
      id: p.id,
      discordUserId: p.discordUserId,
      adminUserId: p.discordUserId,
      status: 'pending' as const,
      reason: undefined,
      createdAt: p.createdAt,
      reviewedAt: undefined,
      expiresAt: p.expiryDate || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    }));
  }

  async getVerificationStats(): Promise<{
    totalUsers: number;
    verifiedUsers: number;
    pendingVerifications: number;
    verificationRate: number;
    todayVerifications: number;
    weekVerifications: number;
  }> {
    const verifications = await this.lockManager.atomicRead('admin-verifications.json');
    const history = await this.lockManager.atomicRead('verification-history.json');

    const totalUsers = verifications.length;
    const verifiedUsers = verifications.filter((v: AdminVerificationWithFingerprint) =>
      v.isActive !== undefined && v.isActive).length;
    const pendingVerifications = verifications.filter((v: AdminVerificationWithFingerprint) =>
      v.isActive === undefined || !v.isActive).length;

    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const weekAgo = new Date(today);
    weekAgo.setDate(weekAgo.getDate() - 7);

    const todayVerifications = history.filter((h: any) =>
      h.success && new Date(h.timestamp) >= today
    ).length;

    const weekVerifications = history.filter((h: any) =>
      h.success && new Date(h.timestamp) >= weekAgo
    ).length;

    const verificationRate = totalUsers > 0 ? Math.round((verifiedUsers / totalUsers) * 100) : 0;

    return {
      totalUsers,
      verifiedUsers,
      pendingVerifications,
      verificationRate,
      todayVerifications,
      weekVerifications,
    };
  }

  async approveVerification(discordUserId: string, adminUserId: string): Promise<boolean> {
    try {
      const verification: AdminVerificationWithFingerprint = {
        id: randomBytes(32).toString('hex'),
        discordUserId,
        uniqueIdentifier: `approved_${discordUserId}_${Date.now()}`,
        passportFingerprint: `approved_fingerprint_${discordUserId}_${Date.now()}`,
        isActive: true,
        lastVerified: new Date(),
        createdAt: new Date(),
        expiryDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      };

      const historyRecord = {
        id: randomBytes(32).toString('hex'),
        discordUserId,
        success: true,
        timestamp: new Date(),
        errorMessage: null,
      };

      // Use transaction to ensure atomicity across multiple files
      await this.lockManager.executeTransaction(['admin-verifications.json', 'verification-history.json'], async (tx) => {
        const verifications = await tx.read('admin-verifications.json');
        const history = await tx.read('verification-history.json');

        const index = verifications.findIndex((v: AdminVerificationWithFingerprint) => v.discordUserId === discordUserId);

        if (index >= 0) {
          verifications[index] = { ...verifications[index], ...verification };
        } else {
          verifications.push(verification);
        }

        history.push(historyRecord);

        await tx.write('admin-verifications.json', verifications);
        await tx.write('verification-history.json', history);
      });

      logger.info(`JSON DB: Verification approved for user ${discordUserId} by admin ${adminUserId}`);
      return true;
    } catch (error) {
      logger.error('JSON DB: Error approving verification:', error instanceof Error ? error : new Error(String(error)));
      return false;
    }
  }

  async rejectVerification(discordUserId: string, adminUserId: string, reason: string): Promise<boolean> {
    try {
      const verification: AdminVerificationWithFingerprint = {
        id: randomBytes(32).toString('hex'),
        discordUserId,
        uniqueIdentifier: `rejected_${discordUserId}_${Date.now()}`,
        passportFingerprint: `rejected_fingerprint_${discordUserId}_${Date.now()}`,
        isActive: false,
        lastVerified: new Date(),
        createdAt: new Date(),
        expiryDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      };

      const historyRecord = {
        id: randomBytes(32).toString('hex'),
        discordUserId,
        success: false,
        timestamp: new Date(),
        errorMessage: reason,
      };

      // Use transaction to ensure atomicity across multiple files
      await this.lockManager.executeTransaction(['admin-verifications.json', 'verification-history.json'], async (tx) => {
        const verifications = await tx.read('admin-verifications.json');
        const history = await tx.read('verification-history.json');

        const index = verifications.findIndex((v: AdminVerificationWithFingerprint) => v.discordUserId === discordUserId);

        if (index >= 0) {
          verifications[index] = { ...verifications[index], ...verification };
        } else {
          verifications.push(verification);
        }

        history.push(historyRecord);

        await tx.write('admin-verifications.json', verifications);
        await tx.write('verification-history.json', history);
      });

      logger.info(`JSON DB: Verification rejected for user ${discordUserId} by admin ${adminUserId}`);
      return true;
    } catch (error) {
      logger.error('JSON DB: Error rejecting verification:', error instanceof Error ? error : new Error(String(error)));
      return false;
    }
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
      logger.error('JSON DB: Failed to perform session cleanup:', error instanceof Error ? error : new Error(String(error)));
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
      logger.error('JSON DB: Failed to get session health stats:', error instanceof Error ? error : new Error(String(error)));
      throw new Error('Failed to retrieve session health statistics');
    }
  }

  async cleanupExpiredSessions(): Promise<number> {
    try {
      const result = await sessionManager.cleanupExpiredSessions();
      if (result.errors.length > 0) {
        logger.warn('JSON DB: Session cleanup errors:', result.errors);
      }
      return result.deletedCount;
    } catch (error) {
      logger.error('JSON DB: Failed to cleanup expired sessions:', error instanceof Error ? error : new Error(String(error)));
      return 0;
    }
  }

  async cleanupExpiredAdminVerifications(): Promise<number> {
    try {
      const result = await sessionManager.cleanupExpiredAdminVerifications();
      if (result.errors.length > 0) {
        logger.warn('JSON DB: Admin verification cleanup errors:', result.errors);
      }
      return result.deactivatedCount;
    } catch (error) {
      logger.error('JSON DB: Failed to cleanup expired admin verifications:', error instanceof Error ? error : new Error(String(error)));
      return 0;
    }
  }

  /**
   * Execute a database transaction
   */
  async executeTransaction(resourceNames: string[], operations: (tx: any) => Promise<void>): Promise<void> {
    await this.lockManager.executeTransaction(resourceNames, operations);
  }

  /**
   * Read a database file atomically
   */
  async findVerificationSession(sessionId: string): Promise<any | null> {
    try {
      const sessions = await this.lockManager.atomicRead('verification-sessions.json');
      return sessions.find((s: any) => s.id === sessionId) || null;
    } catch (error) {
      logger.error('JSON DB: Error finding verification session:', error instanceof Error ? error : new Error(String(error)));
      return null;
    }
  }

  async invalidateAndPersistSessionSync(tx: any, sessionId: string, session: any): Promise<void> {
    const sessions = await tx.read('verification-sessions.json');
    const index = sessions.findIndex((s: any) => s.id === sessionId);
    if (index >= 0) {
      sessions[index].used = true;
      sessions[index].usageCount = session.usageCount;
      sessions[index].lastUsedAt = new Date().toISOString();
      await tx.write('verification-sessions.json', sessions);
    }
  }

  async readFile(filename: string): Promise<any[]> {
    return await this.lockManager.atomicRead(filename);
  }

  /**
   * Write a database file atomically
   */
  async writeFile(filename: string, data: any): Promise<void> {
    await this.lockManager.atomicWrite(filename, data);
  }

  /**
   * Initialize security tables (no-op for JSON driver)
   */
  async initializeSecurityTables(): Promise<void> {
    // JSON driver doesn't need security table initialization
    logger.debug('Security tables initialization not required for JSON driver');
  }
  async disconnect(): Promise<void> {
    try {
      // JSON driver doesn't maintain persistent connections, so no-op
      logger.info('JSON database driver disconnected (no-op)');
    } catch (error) {
      logger.error('Error disconnecting JSON database:', error instanceof Error ? error : new Error(String(error)));
    }
  }
}