import Database from 'better-sqlite3';
import * as path from 'path';
import * as crypto from 'crypto';
import {
  DatabaseOperations,
  VerificationSession,
  AdminVerification,
  VerificationHistory
} from './interfaces';
import { logger } from '../utils/logger';

export class SQLiteDatabaseDriver implements DatabaseOperations {
  private db: Database.Database;
  private dbPath: string;

  constructor(dbPath?: string) {
    this.dbPath = dbPath || path.resolve(__dirname, '..', '..', '..', 'database.sqlite');

    try {
      this.db = new Database(this.dbPath);

      // Enable WAL mode to prevent writer starvation and solve lock contention issues
      this.db.pragma('journal_mode = WAL');
      this.db.pragma('synchronous = NORMAL');
      this.db.pragma('cache_size = 1000');
      this.db.pragma('foreign_keys = ON');

      logger.info(`SQLite database initialized at: ${this.dbPath} with WAL mode enabled`);
    } catch (error) {
      logger.error('Failed to initialize SQLite database:', error);
      throw new Error(`SQLite database initialization failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async initializeDatabase(): Promise<boolean> {
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
      return true;
    } catch (error) {
      logger.error('Failed to initialize SQLite database schema:', error);
      return false;
    }
  }

  async healthCheck(): Promise<boolean> {
    try {
      const stmt = this.db.prepare('SELECT 1 as health_check');
      const result = stmt.get() as any;
      return result.health_check === 1;
    } catch (error) {
      logger.error('SQLite health check failed:', error);
      return false;
    }
  }

  async findVerificationSession(id: string): Promise<VerificationSession | null> {
    try {
      const stmt = this.db.prepare(`
        SELECT id, discord_user_id, token, status, created_at, expires_at, used, attempts, maxAttempts
        FROM verification_sessions
        WHERE id = ?
      `);

      const row = stmt.get(id) as any;
      if (!row) return null;

      return {
        id: row.id,
        discordUserId: row.discord_user_id,
        token: row.token,
        status: row.status,
        createdAt: new Date(row.created_at),
        expiresAt: new Date(row.expires_at),
        used: Boolean(row.used),
        attempts: Number(row.attempts),
        maxAttempts: Number(row.maxAttempts),
        bindingHash: row.binding_hash || "",
        lastContextHash: row.last_context_hash || ""
      };
    } catch (error) {
      logger.error('Error finding verification session:', error);
      throw new Error('Failed to find verification session');
    }
  }

  async createVerificationSession(session: Omit<VerificationSession, 'createdAt'>): Promise<VerificationSession> {
    try {
      const stmt = this.db.prepare(`
        INSERT INTO verification_sessions (id, discord_user_id, token, status, expires_at, used, attempts, maxAttempts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const newSession: VerificationSession = {
        ...session,
        createdAt: new Date(),
        attempts: session.attempts ?? 0,
        maxAttempts: session.maxAttempts ?? 3
      };

      stmt.run(
        newSession.id,
        newSession.discordUserId,
        newSession.token,
        newSession.status,
        newSession.expiresAt.toISOString(),
        newSession.used ? 1 : 0,
        newSession.attempts,
        newSession.maxAttempts
      );

      logger.debug(`Created verification session for user ${session.discordUserId}`);
      return newSession;
    } catch (error) {
      logger.error('Error creating verification session:', error);
      throw new Error('Failed to create verification session');
    }
  }

  async updateVerificationSession(id: string, updates: Partial<VerificationSession>): Promise<VerificationSession | null> {
    try {
      const existing = await this.findVerificationSession(id);
      if (!existing) return null;

      const updated: VerificationSession = { ...existing, ...updates };

      const stmt = this.db.prepare(`
        UPDATE verification_sessions
        SET discord_user_id = ?, token = ?, status = ?, expires_at = ?, used = ?, attempts = ?, maxAttempts = ?
        WHERE id = ?
      `);

      stmt.run(
        updated.discordUserId,
        updated.token,
        updated.status,
        updated.expiresAt.toISOString(),
        updated.used ? 1 : 0,
        updated.attempts,
        updated.maxAttempts,
        id
      );

      return updated;
    } catch (error) {
      logger.error('Error updating verification session:', error);
      throw new Error('Failed to update verification session');
    }
  }

  async markSessionAsUsed(id: string): Promise<boolean> {
    logger.info(`Session ${id} invalidated for security - marking as used`);
    const result = await this.updateVerificationSession(id, { used: true });
    return result !== null;
  }

  async findAdminVerification(discordUserId: string): Promise<AdminVerification | null> {
    try {
      const stmt = this.db.prepare(`
        SELECT id, discord_user_id, passport_fingerprint, unique_identifier, is_active, last_verified, created_at
        FROM admin_verifications
        WHERE discord_user_id = ?
      `);

      const row = stmt.get(discordUserId) as any;
      if (!row) return null;

      return {
        id: row.id,
        discordUserId: row.discord_user_id,
        passportFingerprint: row.passport_fingerprint || '',
        uniqueIdentifier: row.unique_identifier || '',
        isActive: Boolean(row.is_active),
        lastVerified: new Date(row.last_verified),
        createdAt: new Date(row.created_at)
      };
    } catch (error) {
      logger.error('Error finding admin verification:', error);
      throw new Error('Failed to find admin verification');
    }
  }

  async findVerificationByUniqueIdentifier(uniqueIdentifier: string): Promise<AdminVerification | null> {
    try {
      const stmt = this.db.prepare(`
        SELECT id, discord_user_id, passport_fingerprint, unique_identifier, is_active, last_verified, created_at
        FROM admin_verifications
        WHERE unique_identifier = ?
      `);

      const row = stmt.get(uniqueIdentifier) as any;
      if (!row) return null;

      return {
        id: row.id,
        discordUserId: row.discord_user_id,
        passportFingerprint: row.passport_fingerprint || '',
        uniqueIdentifier: row.unique_identifier || '',
        isActive: Boolean(row.is_active),
        lastVerified: new Date(row.last_verified),
        createdAt: new Date(row.created_at)
      };
    } catch (error) {
      logger.error('Error finding verification by unique identifier:', error);
      throw new Error('Failed to find verification by unique identifier');
    }
  }

  async findVerificationByFingerprint(passportFingerprint: string): Promise<AdminVerification | null> {
    try {
      const stmt = this.db.prepare(`
        SELECT id, discord_user_id, passport_fingerprint, unique_identifier, is_active, last_verified, created_at
        FROM admin_verifications
        WHERE passport_fingerprint = ?
      `);

      const row = stmt.get(passportFingerprint) as any;
      if (!row) return null;

      return {
        id: row.id,
        discordUserId: row.discord_user_id,
        passportFingerprint: row.passport_fingerprint || '',
        uniqueIdentifier: row.unique_identifier || '',
        isActive: Boolean(row.is_active),
        lastVerified: new Date(row.last_verified),
        createdAt: new Date(row.created_at)
      };
    } catch (error) {
      logger.error('Error finding verification by fingerprint:', error);
      throw new Error('Failed to find verification by fingerprint');
    }
  }

  async upsertAdminVerification(verification: Omit<AdminVerification, 'createdAt'>): Promise<AdminVerification> {
    try {
      const transaction = this.db.transaction(() => {
        const upsertStmt = this.db.prepare(`
          INSERT OR REPLACE INTO admin_verifications
          (id, discord_user_id, passport_fingerprint, unique_identifier, is_active, last_verified, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `);

        const now = new Date().toISOString();
        const id = crypto.randomUUID();

        upsertStmt.run(
          id,
          verification.discordUserId,
          verification.passportFingerprint,
          verification.uniqueIdentifier,
          verification.isActive ? 1 : 0,
          verification.lastVerified.toISOString(),
          now
        );

        // Also create history entry
        const historyStmt = this.db.prepare(`
          INSERT INTO verification_history (id, discord_user_id, success, error_message, created_at)
          VALUES (?, ?, ?, ?, ?)
        `);

        historyStmt.run(
          crypto.randomUUID(),
          verification.discordUserId,
          verification.isActive ? 1 : 0,
          null,
          now
        );
      });

      transaction();

      // Return the verification (need to fetch it back since we used INSERT OR REPLACE)
      const result = await this.findAdminVerification(verification.discordUserId);
      if (!result) {
        throw new Error('Failed to retrieve upserted verification');
      }

      return result;
    } catch (error) {
      logger.error('Error upserting admin verification:', error);
      throw new Error('Failed to upsert admin verification');
    }
  }

  async createVerificationHistory(history: Omit<VerificationHistory, 'id' | 'createdAt'>): Promise<VerificationHistory> {
    try {
      const stmt = this.db.prepare(`
        INSERT INTO verification_history (id, discord_user_id, success, error_message, created_at)
        VALUES (?, ?, ?, ?, ?)
      `);

      const id = crypto.randomUUID();
      const now = new Date().toISOString();

      stmt.run(
        id,
        history.discordUserId,
        history.success ? 1 : 0,
        history.errorMessage || null,
        now
      );

      return {
        id,
        discordUserId: history.discordUserId,
        success: history.success,
        errorMessage: history.errorMessage,
        timestamp: new Date(now),
        createdAt: new Date(now)
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
    // SQLite handles transactions automatically with better-sqlite3
    // For this implementation, we'll wrap the function in a transaction
    const transaction = this.db.transaction(() => {
      return transactionFn(this.db);
    });

    return transaction();
  }

  // Synchronous database operations for use within transactions
  invalidateAndPersistSessionSync(tx: Database.Database, sessionValidation: any): void {
    try {
      const markUsedStmt = tx.prepare(`
        UPDATE verification_sessions
        SET used = 1
        WHERE id = ?
      `);
      markUsedStmt.run(sessionValidation.session.id);
      logger.debug(`Session ${sessionValidation.session.id} invalidated synchronously`);
    } catch (error) {
      logger.error('Error invalidating session synchronously:', error);
      throw new Error('Failed to invalidate session synchronously');
    }
  }

  upsertAdminVerificationSync(tx: Database.Database, verification: Omit<AdminVerification, 'createdAt'>): AdminVerification {
    try {
      const upsertStmt = tx.prepare(`
        INSERT OR REPLACE INTO admin_verifications
        (id, discord_user_id, passport_fingerprint, unique_identifier, is_active, last_verified, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);

      const now = new Date().toISOString();
      const id = crypto.randomUUID();

      upsertStmt.run(
        id,
        verification.discordUserId,
        verification.passportFingerprint,
        verification.uniqueIdentifier,
        verification.isActive ? 1 : 0,
        verification.lastVerified.toISOString(),
        now
      );

      // Return the verification object (don't fetch back since we know what we inserted)
      return {
        id,
        discordUserId: verification.discordUserId,
        passportFingerprint: verification.passportFingerprint,
        uniqueIdentifier: verification.uniqueIdentifier,
        isActive: verification.isActive,
        lastVerified: verification.lastVerified,
        createdAt: new Date(now)
      };
    } catch (error) {
      logger.error('Error upserting admin verification synchronously:', error);
      throw new Error('Failed to upsert admin verification synchronously');
    }
  }

  createVerificationHistorySync(tx: Database.Database, history: Omit<VerificationHistory, 'id' | 'createdAt'>): VerificationHistory {
    try {
      const stmt = tx.prepare(`
        INSERT INTO verification_history (id, discord_user_id, success, error_message, created_at)
        VALUES (?, ?, ?, ?, ?)
      `);

      const id = crypto.randomUUID();
      const now = new Date().toISOString();

      stmt.run(
        id,
        history.discordUserId,
        history.success ? 1 : 0,
        history.errorMessage || null,
        now
      );

      return {
        id,
        discordUserId: history.discordUserId,
        success: history.success,
        errorMessage: history.errorMessage,
        timestamp: new Date(now),
        createdAt: new Date(now)
      };
    } catch (error) {
      logger.error('Error creating verification history synchronously:', error);
      throw new Error('Failed to create verification history synchronously');
    }
  }

  close(): void {
    if (this.db) {
      this.db.close();
      logger.info('SQLite database connection closed');
    }
  }
}