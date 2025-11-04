import * as path from 'path';
import Database from 'better-sqlite3';
import { randomBytes } from 'crypto';
import { VerificationSession, UserVerification, AdminVerification } from '@shared/types';
import { RateLimiter } from '@shared/utils';
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
}

// SQLite Database Driver with partitioned history tables
export class SQLiteDatabaseDriver implements IDatabaseDriver {
  private db: Database.Database;
  private verificationRateLimiter: RateLimiter;
  private databasePath: string;

  constructor(databasePath?: string) {
    // Securely validate database path
    this.databasePath = databasePath ? path.resolve(__dirname, '..', '..', '..', databasePath) : path.resolve(__dirname, '..', '..', '..', 'database.sqlite');

    // Initialize rate limiter
    this.verificationRateLimiter = new RateLimiter(3, 60000); // 3 attempts per minute

    try {
      // Initialize SQLite database with WAL mode for concurrent read/write
      this.db = new Database(this.databasePath);
      this.db.pragma('journal_mode = WAL');
      this.db.pragma('synchronous = NORMAL');
      this.db.pragma('cache_size = 1000');
      this.db.pragma('foreign_keys = ON');

      logger.info(`SQLite database initialized at: ${this.databasePath}`);
    } catch (error) {
      logger.error('Failed to initialize SQLite database:', error instanceof Error ? error : new Error(String(error)));
      throw new Error(`SQLite database initialization failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async initializeDatabase(): Promise<void> {
    try {
      // Create tables if they don't exist
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS verification_sessions (
          id TEXT PRIMARY KEY,
          discord_user_id TEXT NOT NULL,
          token TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          expires_at DATETIME NOT NULL,
          used BOOLEAN DEFAULT FALSE,
          attempts INTEGER NOT NULL DEFAULT 0,
          maxAttempts INTEGER NOT NULL DEFAULT 3
        );

        CREATE TABLE IF NOT EXISTS admin_verifications (
          id TEXT PRIMARY KEY,
          discord_user_id TEXT NOT NULL UNIQUE,
          passport_fingerprint TEXT,
          unique_identifier TEXT,
          is_active BOOLEAN DEFAULT FALSE,
          last_verified DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS verification_history (
          id TEXT PRIMARY KEY,
          discord_user_id TEXT NOT NULL,
          success BOOLEAN NOT NULL,
          error_message TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_verification_sessions_discord_user_id ON verification_sessions(discord_user_id);
        CREATE INDEX IF NOT EXISTS idx_verification_sessions_status ON verification_sessions(status);
        CREATE INDEX IF NOT EXISTS idx_admin_verifications_discord_user_id ON admin_verifications(discord_user_id);
        CREATE INDEX IF NOT EXISTS idx_admin_verifications_active ON admin_verifications(is_active);
        CREATE INDEX IF NOT EXISTS idx_verification_history_discord_user_id ON verification_history(discord_user_id);
        CREATE INDEX IF NOT EXISTS idx_verification_history_created_at ON verification_history(created_at);
      `);

      logger.info('SQLite database schema initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize SQLite database schema:', error instanceof Error ? error : new Error(String(error)));
      throw error;
    }
  }

  private createHistoryPartition(monthKey: string): void {
    const tableName = `verification_history_${monthKey.replace('-', '_')}`;
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ${tableName} (
        id TEXT PRIMARY KEY,
        discord_user_id TEXT NOT NULL,
        success BOOLEAN NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        error_message TEXT,
        verification_type TEXT,
        ip_address TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_${tableName}_discord_user_id ON ${tableName}(discord_user_id);
      CREATE INDEX IF NOT EXISTS idx_${tableName}_timestamp ON ${tableName}(timestamp);
      CREATE INDEX IF NOT EXISTS idx_${tableName}_success ON ${tableName}(success);
    `);
    logger.debug(`Created verification history partition table: ${tableName}`);
  }

  private getHistoryTableName(date?: Date): string {
    const targetDate = date || new Date();
    const monthKey = targetDate.toISOString().slice(0, 7).replace('-', '_');
    return `verification_history_${monthKey}`;
  }

  async createVerificationSession(sessionData: Partial<VerificationSession>): Promise<VerificationSession> {
    try {
      // Validate required fields
      if (!sessionData.id || !sessionData.token || !sessionData.discordUserId || !sessionData.expiresAt) {
        throw new Error('Missing required session data fields');
      }

      // Atomic transaction: ensure AdminVerification exists before creating session
      const transaction = this.db.transaction(() => {
        // Upsert AdminVerification record
        const upsertStmt = this.db.prepare(`
          INSERT OR REPLACE INTO admin_verifications
          (id, discord_user_id, passport_fingerprint, unique_identifier, is_active, last_verified, created_at)
          VALUES (?, ?, ?, ?, 0, ?, ?)
        `);

        const verificationId = randomBytes(32).toString('hex');
        const now = new Date().toISOString();

        upsertStmt.run(
          verificationId,
          sessionData.discordUserId,
          `pending_fingerprint_${sessionData.discordUserId}_${Date.now()}`, // Placeholder fingerprint
          `pending_${sessionData.discordUserId}_${Date.now()}`, // Placeholder identifier
          now,
          now
        );

        // Now create the verification session
        const sessionStmt = this.db.prepare(`
          INSERT INTO verification_sessions (id, discord_user_id, token, status, created_at, expires_at, used, attempts, maxAttempts, binding_hash, last_context_hash)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', '')
        `);

        const newSession: VerificationSession = {
          id: sessionData.id!,
          token: sessionData.token!,
          discordUserId: sessionData.discordUserId!,
          status: 'pending',
          createdAt: new Date(),
          expiresAt: sessionData.expiresAt!,
          attempts: sessionData.attempts ?? 0,
          maxAttempts: sessionData.maxAttempts ?? 3,
        };

        sessionStmt.run(
          newSession.id,
          newSession.discordUserId,
          newSession.token,
          newSession.status,
          newSession.createdAt.toISOString(),
          newSession.expiresAt.toISOString(),
          0,
          newSession.attempts,
          newSession.maxAttempts
        );

        return newSession;
      });

      const result = transaction();

      logger.debug(`Created verification session for user ${sessionData.discordUserId}`);
      return result;
    } catch (error) {
      logger.error('SQLite DB: Error creating verification session:', error instanceof Error ? error : new Error(String(error)));
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
      const stmt = this.db.prepare(`
        SELECT id, discord_user_id, passport_fingerprint, unique_identifier, is_active, last_verified, created_at, expiry_date
        FROM admin_verifications
        WHERE discord_user_id = ?
      `);

      const row = stmt.get(discordUserId) as any;
      if (!row) return null;

      return {
        id: row.id,
        discordUserId: row.discord_user_id,
        isVerified: row.is_active,
        verifiedAt: row.last_verified ? new Date(row.last_verified) : undefined,
        lastVerificationDate: new Date(row.created_at),
        expiresAt: row.expiry_date ? new Date(row.expiry_date) : undefined,
        adminVerified: row.is_active,
        adminVerifiedBy: row.discord_user_id,
        adminVerifiedAt: row.last_verified ? new Date(row.last_verified) : undefined,
      };
    } catch (error) {
      logger.error('SQLite DB: Error fetching user verification status:', error instanceof Error ? error : new Error(String(error)));
      throw new Error('Failed to fetch verification status');
    }
  }

  async getPendingVerifications(limit: number = 10): Promise<AdminVerification[]> {
    try {
      const stmt = this.db.prepare(`
        SELECT id, discord_user_id, passport_fingerprint, unique_identifier, is_active, last_verified, created_at, expiry_date
        FROM admin_verifications
        WHERE is_active = 0 OR is_active IS NULL
        ORDER BY created_at DESC
        LIMIT ?
      `);

      const rows = stmt.all(limit) as any[];
      return rows.map(row => ({
        id: row.id,
        discordUserId: row.discord_user_id,
        adminUserId: row.discord_user_id,
        status: 'pending' as const,
        reason: undefined,
        createdAt: new Date(row.created_at),
        reviewedAt: undefined,
        expiresAt: row.expiry_date ? new Date(row.expiry_date) : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      }));
    } catch (error) {
      logger.error('SQLite DB: Error fetching pending verifications:', error instanceof Error ? error : new Error(String(error)));
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
      const totalUsers = this.db.prepare('SELECT COUNT(*) as count FROM admin_verifications').get() as any;
      const verifiedUsers = this.db.prepare('SELECT COUNT(*) as count FROM admin_verifications WHERE is_active = 1').get() as any;

      const pendingVerifications = totalUsers.count - verifiedUsers.count;

      const today = new Date();
      today.setHours(0, 0, 0, 0);
      const weekAgo = new Date(today);
      weekAgo.setDate(weekAgo.getDate() - 7);

      // Get all history tables
      const tables = this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'verification_history_%'").all() as any[];

      let todayVerifications = 0;
      let weekVerifications = 0;

      for (const table of tables) {
        const todayStmt = this.db.prepare(`SELECT COUNT(*) as count FROM ${table.name} WHERE success = 1 AND timestamp >= ?`);
        const weekStmt = this.db.prepare(`SELECT COUNT(*) as count FROM ${table.name} WHERE success = 1 AND timestamp >= ?`);

        todayVerifications += (todayStmt.get(today.toISOString()) as any).count;
        weekVerifications += (weekStmt.get(weekAgo.toISOString()) as any).count;
      }

      const verificationRate = totalUsers.count > 0 ? Math.round((verifiedUsers.count / totalUsers.count) * 100) : 0;

      return {
        totalUsers: totalUsers.count,
        verifiedUsers: verifiedUsers.count,
        pendingVerifications,
        verificationRate,
        todayVerifications,
        weekVerifications,
      };
    } catch (error) {
      logger.error('SQLite DB: Error fetching verification stats:', error instanceof Error ? error : new Error(String(error)));
      throw new Error('Failed to fetch verification statistics');
    }
  }

  async approveVerification(discordUserId: string, adminUserId: string): Promise<boolean> {
    try {
      const transaction = this.db.transaction(() => {
        const upsertStmt = this.db.prepare(`
          INSERT OR REPLACE INTO admin_verifications
          (id, discord_user_id, passport_fingerprint, unique_identifier, is_active, last_verified, created_at, expiry_date)
          VALUES (?, ?, ?, ?, 1, ?, ?, ?)
        `);

        const id = randomBytes(32).toString('hex');
        const now = new Date().toISOString();
        const expiryDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

        upsertStmt.run(
          id,
          discordUserId,
          `approved_fingerprint_${discordUserId}_${Date.now()}`,
          `approved_${discordUserId}_${Date.now()}`,
          now,
          now,
          expiryDate
        );

        // Insert into partitioned history table
        const historyTable = this.getHistoryTableName();
        this.ensureHistoryPartition(historyTable);

        const historyStmt = this.db.prepare(`
          INSERT INTO ${historyTable} (id, discord_user_id, success, timestamp, error_message)
          VALUES (?, ?, 1, ?, NULL)
        `);

        historyStmt.run(randomBytes(32).toString('hex'), discordUserId, now);
      });

      transaction();
      logger.info(`SQLite DB: Verification approved for user ${discordUserId} by admin ${adminUserId}`);
      return true;
    } catch (error) {
      logger.error('SQLite DB: Error approving verification:', error instanceof Error ? error : new Error(String(error)));
      return false;
    }
  }

  async rejectVerification(discordUserId: string, adminUserId: string, reason: string): Promise<boolean> {
    try {
      const transaction = this.db.transaction(() => {
        const upsertStmt = this.db.prepare(`
          INSERT OR REPLACE INTO admin_verifications
          (id, discord_user_id, passport_fingerprint, unique_identifier, is_active, last_verified, created_at, expiry_date)
          VALUES (?, ?, ?, ?, 0, ?, ?, ?)
        `);

        const id = randomBytes(32).toString('hex');
        const now = new Date().toISOString();
        const expiryDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

        upsertStmt.run(
          id,
          discordUserId,
          `rejected_fingerprint_${discordUserId}_${Date.now()}`,
          `rejected_${discordUserId}_${Date.now()}`,
          now,
          now,
          expiryDate
        );

        // Insert into partitioned history table
        const historyTable = this.getHistoryTableName();
        this.ensureHistoryPartition(historyTable);

        const historyStmt = this.db.prepare(`
          INSERT INTO ${historyTable} (id, discord_user_id, success, timestamp, error_message)
          VALUES (?, ?, 0, ?, ?)
        `);

        historyStmt.run(randomBytes(32).toString('hex'), discordUserId, now, reason);
      });

      transaction();
      logger.info(`SQLite DB: Verification rejected for user ${discordUserId} by admin ${adminUserId}`);
      return true;
    } catch (error) {
      logger.error('SQLite DB: Error rejecting verification:', error instanceof Error ? error : new Error(String(error)));
      return false;
    }
  }

  private ensureHistoryPartition(tableName: string): void {
    try {
      this.db.prepare(`SELECT 1 FROM ${tableName} LIMIT 1`).get();
    } catch (error) {
      // Table doesn't exist, create it
      const monthKey = tableName.replace('verification_history_', '');
      this.createHistoryPartition(monthKey.replace('_', '-'));
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
      logger.error('SQLite DB: Failed to perform session cleanup:', error instanceof Error ? error : new Error(String(error)));
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
      logger.error('SQLite DB: Failed to get session health stats:', error instanceof Error ? error : new Error(String(error)));
      throw new Error('Failed to retrieve session health statistics');
    }
  }

  async cleanupExpiredSessions(): Promise<number> {
    try {
      const result = await sessionManager.cleanupExpiredSessions();
      if (result.errors.length > 0) {
        logger.warn('SQLite DB: Session cleanup errors:', result.errors);
      }
      return result.deletedCount;
    } catch (error) {
      logger.error('SQLite DB: Failed to cleanup expired sessions:', error instanceof Error ? error : new Error(String(error)));
      return 0;
    }
  }

  async cleanupExpiredAdminVerifications(): Promise<number> {
    try {
      const result = await sessionManager.cleanupExpiredAdminVerifications();
      if (result.errors.length > 0) {
        logger.warn('SQLite DB: Admin verification cleanup errors:', result.errors);
      }
      return result.deactivatedCount;
    } catch (error) {
      logger.error('SQLite DB: Failed to cleanup expired admin verifications:', error instanceof Error ? error : new Error(String(error)));
      return 0;
    }
  }

  async executeTransaction(_: string[], operations: (tx: any) => Promise<void>): Promise<void> {
    // SQLite handles transactions internally, so we wrap the operations in a transaction
    const transaction = this.db.transaction(() => {
      // Execute operations - SQLite transactions are automatic
      // In a more complex scenario, we'd need to adapt the transaction interface
      return operations(this.db);
    });
    transaction();
  }

  async findVerificationSession(sessionId: string): Promise<any | null> {
    try {
      const stmt = this.db.prepare(`
        SELECT id, discord_user_id, token, status, created_at, expires_at, used, attempts, maxAttempts
        FROM verification_sessions
        WHERE id = ?
      `);

      const row = stmt.get(sessionId) as any;
      if (!row) return null;

      return {
        id: row.id,
        discordUserId: row.discord_user_id,
        token: row.token,
        status: row.status,
        createdAt: new Date(row.created_at),
        expiresAt: new Date(row.expires_at),
        used: Boolean(row.used),
        attempts: row.attempts,
        maxAttempts: row.maxAttempts,
      };
    } catch (error) {
      logger.error('SQLite DB: Error finding verification session:', error instanceof Error ? error : new Error(String(error)));
      return null;
    }
  }

  async invalidateAndPersistSessionSync(sessionId: string): Promise<void> {
    const stmt = this.db.prepare(`
      UPDATE verification_sessions
      SET used = 1, last_used_at = ?
      WHERE id = ?
    `);
    stmt.run(new Date().toISOString(), sessionId);
  }

  async readFile(_: string): Promise<any[]> {
    // SQLite doesn't use files in the same way - this method is for compatibility
    // In practice, this would need to be handled differently or removed
    throw new Error('readFile not implemented for SQLite driver');
  }

  async writeFile(_: string, __: any): Promise<void> {
    // SQLite doesn't use files in the same way - this method is for compatibility
    // In practice, this would need to be handled differently or removed
    throw new Error('writeFile not implemented for SQLite driver');
  }

  async initializeSecurityTables(): Promise<void> {
    // SQLite driver doesn't need separate security table initialization
    logger.debug('Security tables initialization not required for SQLite driver');
  }

  // Close database connection when needed
  close(): void {
    if (this.db) {
      this.db.close();
      logger.info('SQLite database connection closed');
    }
  }
}