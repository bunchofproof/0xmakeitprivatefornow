import * as fs from 'fs';
import * as path from 'path';
import Database from 'better-sqlite3';
import { logger } from './logger';

interface MigrationResult {
  success: boolean;
  sessionsMigrated: number;
  adminVerificationsMigrated: number;
  historyRecordsMigrated: number;
  errors: string[];
  backupPath?: string;
}

/**
 * Utility class for migrating data from JSON files to SQLite database
 */
export class MigrationUtility {
  private jsonDatabaseDir: string;
  private sqlitePath: string;
  private db: Database.Database;

  constructor(jsonDatabaseDir?: string, sqlitePath?: string) {
    this.jsonDatabaseDir = jsonDatabaseDir || path.join(process.cwd(), 'database');
    this.sqlitePath = sqlitePath || path.join(this.jsonDatabaseDir, 'database.sqlite');

    // Initialize SQLite database
    this.db = new Database(this.sqlitePath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this.db.pragma('foreign_keys = ON');
  }

  /**
   * Perform complete migration from JSON to SQLite
   */
  async migrateData(): Promise<MigrationResult> {
    const result: MigrationResult = {
      success: false,
      sessionsMigrated: 0,
      adminVerificationsMigrated: 0,
      historyRecordsMigrated: 0,
      errors: []
    };

    try {
      logger.info('Starting data migration from JSON to SQLite');

      // Step 1: Create backup of JSON files
      result.backupPath = await this.createBackup();

      // Step 2: Initialize SQLite schema
      this.initializeSQLiteSchema();

      // Step 3: Migrate verification sessions
      result.sessionsMigrated = this.migrateVerificationSessions();

      // Step 4: Migrate admin verifications
      result.adminVerificationsMigrated = this.migrateAdminVerifications();

      // Step 5: Migrate verification history
      result.historyRecordsMigrated = this.migrateVerificationHistory();

      // Step 6: Validate migration
      if (this.validateMigration()) {
        result.success = true;
        logger.info('Data migration completed successfully');
      } else {
        result.errors.push('Migration validation failed');
        logger.error('Migration validation failed');
      }

    } catch (error) {
      const errorMessage = `Migration failed: ${error instanceof Error ? error.message : String(error)}`;
      result.errors.push(errorMessage);
      logger.error('Migration error:', error instanceof Error ? error : new Error(String(error)));
    } finally {
      this.db.close();
    }

    return result;
  }

  /**
   * Create backup of existing JSON files
   */
  private async createBackup(): Promise<string> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupDir = path.join(this.jsonDatabaseDir, `backup-${timestamp}`);

    if (!fs.existsSync(backupDir)) {
      fs.mkdirSync(backupDir, { recursive: true });
    }

    const filesToBackup = [
      'verification-sessions.json',
      'admin-verifications.json',
      'verification-history.json'
    ];

    for (const file of filesToBackup) {
      const sourcePath = path.join(this.jsonDatabaseDir, file);
      if (fs.existsSync(sourcePath)) {
        const destPath = path.join(backupDir, file);
        fs.copyFileSync(sourcePath, destPath);
        logger.debug(`Backed up ${file} to ${destPath}`);
      }
    }

    logger.info(`Created backup at: ${backupDir}`);
    return backupDir;
  }

  /**
   * Initialize SQLite schema with partitioned tables
   */
  private initializeSQLiteSchema(): void {
    // Create main tables
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS verification_sessions (
        id TEXT PRIMARY KEY,
        token TEXT NOT NULL,
        discord_user_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        attempts INTEGER DEFAULT 0,
        max_attempts INTEGER DEFAULT 3
      );

      CREATE TABLE IF NOT EXISTS admin_verifications (
        id TEXT PRIMARY KEY,
        discord_user_id TEXT NOT NULL UNIQUE,
        passport_fingerprint TEXT,
        unique_identifier TEXT,
        is_active BOOLEAN DEFAULT FALSE,
        last_verified DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expiry_date DATETIME
      );

      CREATE INDEX IF NOT EXISTS idx_admin_verifications_discord_user_id ON admin_verifications(discord_user_id);
      CREATE INDEX IF NOT EXISTS idx_admin_verifications_active ON admin_verifications(is_active);
      CREATE INDEX IF NOT EXISTS idx_verification_sessions_discord_user_id ON verification_sessions(discord_user_id);
      CREATE INDEX IF NOT EXISTS idx_verification_sessions_status ON verification_sessions(status);
    `);

    // Create initial partition table for current month
    const currentMonth = new Date().toISOString().slice(0, 7); // YYYY-MM format
    this.createHistoryPartition(currentMonth);

    logger.debug('SQLite schema initialized');
  }

  /**
   * Create a history partition table for the given month
   */
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
  }

  /**
   * Migrate verification sessions from JSON to SQLite
   */
  private migrateVerificationSessions(): number {
    try {
      const sessionsPath = path.join(this.jsonDatabaseDir, 'verification-sessions.json');

      if (!fs.existsSync(sessionsPath)) {
        logger.warn('Verification sessions file not found, skipping session migration');
        return 0;
      }

      const sessionsData = JSON.parse(fs.readFileSync(sessionsPath, 'utf8'));

      if (!Array.isArray(sessionsData)) {
        throw new Error('Invalid verification sessions data format');
      }

      const insertStmt = this.db.prepare(`
        INSERT OR REPLACE INTO verification_sessions
        (id, token, discord_user_id, status, created_at, expires_at, attempts, max_attempts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);

      let migratedCount = 0;
      for (const session of sessionsData) {
        try {
          insertStmt.run(
            session.id,
            session.token,
            session.discordUserId,
            session.status || 'pending',
            session.createdAt || new Date().toISOString(),
            session.expiresAt,
            session.attempts || 0,
            session.maxAttempts || 3
          );
          migratedCount++;
        } catch (error) {
          logger.warn(`Failed to migrate session ${session.id}:`, error);
        }
      }

      logger.info(`Migrated ${migratedCount} verification sessions`);
      return migratedCount;

    } catch (error) {
      logger.error('Error migrating verification sessions:', error instanceof Error ? error : new Error(String(error)));
      throw error;
    }
  }

  /**
   * Migrate admin verifications from JSON to SQLite
   */
  private migrateAdminVerifications(): number {
    try {
      const verificationsPath = path.join(this.jsonDatabaseDir, 'admin-verifications.json');

      if (!fs.existsSync(verificationsPath)) {
        logger.warn('Admin verifications file not found, skipping verification migration');
        return 0;
      }

      const verificationsData = JSON.parse(fs.readFileSync(verificationsPath, 'utf8'));

      if (!Array.isArray(verificationsData)) {
        throw new Error('Invalid admin verifications data format');
      }

      const insertStmt = this.db.prepare(`
        INSERT OR REPLACE INTO admin_verifications
        (id, discord_user_id, passport_fingerprint, unique_identifier, is_active, last_verified, created_at, expiry_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);

      let migratedCount = 0;
      for (const verification of verificationsData) {
        try {
          insertStmt.run(
            verification.id,
            verification.discordUserId,
            verification.passportFingerprint || null,
            verification.uniqueIdentifier || null,
            verification.isActive ? 1 : 0,
            verification.lastVerified || null,
            verification.createdAt || new Date().toISOString(),
            verification.expiryDate || null
          );
          migratedCount++;
        } catch (error) {
          logger.warn(`Failed to migrate admin verification ${verification.id}:`, error);
        }
      }

      logger.info(`Migrated ${migratedCount} admin verifications`);
      return migratedCount;

    } catch (error) {
      logger.error('Error migrating admin verifications:', error instanceof Error ? error : new Error(String(error)));
      throw error;
    }
  }

  /**
   * Migrate verification history from JSON to SQLite
   */
  private migrateVerificationHistory(): number {
    try {
      const historyPath = path.join(this.jsonDatabaseDir, 'verification-history.json');

      if (!fs.existsSync(historyPath)) {
        logger.warn('Verification history file not found, skipping history migration');
        return 0;
      }

      const historyData = JSON.parse(fs.readFileSync(historyPath, 'utf8'));

      if (!Array.isArray(historyData)) {
        throw new Error('Invalid verification history data format');
      }

      // Group history records by month for partitioning
      const recordsByMonth: Record<string, any[]> = {};

      for (const record of historyData) {
        const recordDate = record.timestamp ? new Date(record.timestamp) : new Date();
        const monthKey = recordDate.toISOString().slice(0, 7); // YYYY-MM format

        if (!recordsByMonth[monthKey]) {
          recordsByMonth[monthKey] = [];
        }
        recordsByMonth[monthKey].push(record);
      }

      let totalMigrated = 0;

      // Create partitions and migrate data
      for (const [monthKey, records] of Object.entries(recordsByMonth)) {
        this.createHistoryPartition(monthKey);

        const tableName = `verification_history_${monthKey.replace('-', '_')}`;
        const insertStmt = this.db.prepare(`
          INSERT OR REPLACE INTO ${tableName}
          (id, discord_user_id, success, timestamp, error_message, verification_type, ip_address)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `);

        for (const record of records) {
          try {
            insertStmt.run(
              record.id,
              record.discordUserId,
              record.success ? 1 : 0,
              record.timestamp || new Date().toISOString(),
              record.errorMessage || null,
              record.verificationType || null,
              record.ipAddress || null
            );
            totalMigrated++;
          } catch (error) {
            logger.warn(`Failed to migrate history record ${record.id}:`, error);
          }
        }
      }

      logger.info(`Migrated ${totalMigrated} verification history records`);
      return totalMigrated;

    } catch (error) {
      logger.error('Error migrating verification history:', error instanceof Error ? error : new Error(String(error)));
      throw error;
    }
  }

  /**
   * Validate migration by comparing record counts
   */
  private validateMigration(): boolean {
    try {
      // Count records in JSON files
      const getJsonRecordCount = (fileName: string): number => {
        const filePath = path.join(this.jsonDatabaseDir, fileName);
        if (!fs.existsSync(filePath)) return 0;
        const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        return Array.isArray(data) ? data.length : 0;
      };

      const jsonSessions = getJsonRecordCount('verification-sessions.json');
      const jsonVerifications = getJsonRecordCount('admin-verifications.json');
      const jsonHistory = getJsonRecordCount('verification-history.json');

      // Count records in SQLite
      const sqliteSessions = this.db.prepare('SELECT COUNT(*) as count FROM verification_sessions').get() as any;
      const sqliteVerifications = this.db.prepare('SELECT COUNT(*) as count FROM admin_verifications').get() as any;

      // Count all history records across partitions
      const historyTables = this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'verification_history_%'").all() as any[];
      let sqliteHistory = 0;
      for (const table of historyTables) {
        const count = this.db.prepare(`SELECT COUNT(*) as count FROM ${table.name}`).get() as any;
        sqliteHistory += count.count;
      }

      const validationPassed =
        sqliteSessions.count >= jsonSessions &&
        sqliteVerifications.count >= jsonVerifications &&
        sqliteHistory >= jsonHistory;

      logger.info(`Migration validation: JSON(${jsonSessions}, ${jsonVerifications}, ${jsonHistory}) -> SQLite(${sqliteSessions.count}, ${sqliteVerifications.count}, ${sqliteHistory})`);

      return validationPassed;

    } catch (error) {
      logger.error('Migration validation failed:', error instanceof Error ? error : new Error(String(error)));
      return false;
    }
  }

  /**
   * Rollback migration by restoring from backup
   */
  async rollbackMigration(backupPath: string): Promise<boolean> {
    try {
      logger.info(`Rolling back migration using backup: ${backupPath}`);

      const filesToRestore = [
        'verification-sessions.json',
        'admin-verifications.json',
        'verification-history.json'
      ];

      for (const file of filesToRestore) {
        const backupFilePath = path.join(backupPath, file);
        const originalFilePath = path.join(this.jsonDatabaseDir, file);

        if (fs.existsSync(backupFilePath)) {
          fs.copyFileSync(backupFilePath, originalFilePath);
          logger.debug(`Restored ${file} from backup`);
        }
      }

      // Close and remove SQLite database
      this.db.close();
      if (fs.existsSync(this.sqlitePath)) {
        fs.unlinkSync(this.sqlitePath);
        logger.debug('Removed SQLite database file');
      }

      logger.info('Migration rollback completed successfully');
      return true;

    } catch (error) {
      logger.error('Migration rollback failed:', error instanceof Error ? error : new Error(String(error)));
      return false;
    }
  }
}

/**
 * Run migration utility from command line
 */
export async function runMigration(jsonDir?: string, sqlitePath?: string): Promise<void> {
  const migrator = new MigrationUtility(jsonDir, sqlitePath);
  const result = await migrator.migrateData();

  console.log('Migration Result:', result);

  if (!result.success) {
    console.error('Migration failed with errors:', result.errors);
    process.exit(1);
  } else {
    console.log('Migration completed successfully!');
  }
}

// CLI usage: node -e "import('./migrationUtility.js').then(m => m.runMigration())"